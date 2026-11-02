//! The decision-model client (step 3): one System One request per call
//! (docs/dev/action-checker.md).
//!
//! Decision models answer a typed yes/no question in one forward pass, no
//! tokens generated. `POST /v1/systemone` takes a `state` and a `questions`
//! map and returns, for a `noul` question, the probability that the answer is
//! `true`. The de-facto API is TypeSafe's; `llama-server` serves the same.
//!
//! The question is fixed by the center. The command or path only ever goes in
//! `state`, so a call cannot rephrase what is asked.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use nerve_proto::link::CenterUrl;

use super::config::ModelConfig;

/// Where the model is and how to reach it.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub url: CenterUrl,
    /// The bearer token, kept out of `state.json` and never shown back.
    pub token: Option<String>,
    /// The model name sent as `model`, if any.
    pub model: Option<String>,
    /// For the center's own local server: how much it reads within the
    /// timeout, so a call it cannot read in time is not sent. An endpoint
    /// has none, as the center does not know its machine.
    pub budget: Option<Arc<ReadBudget>>,
}

impl Endpoint {
    /// Parses `url` (its path is fixed at `/v1/systemone`).
    pub fn parse(
        url: &str,
        token: Option<String>,
        model: Option<String>,
    ) -> Result<Endpoint, String> {
        let url = CenterUrl::parse(url)?;
        Ok(Endpoint {
            url,
            token: token.filter(|t| !t.is_empty()),
            model: model.filter(|m| !m.is_empty()),
            budget: None,
        })
    }
}

/// A request of at most this many tokens is sent to the local server
/// whatever its measured speed: every release before #178 sent those (its
/// server read 512 tokens at a time), and sending ordinary calls keeps the
/// speed measured. Only a longer one is held to the timeout.
pub const ALWAYS_SENT_TOKENS: usize = 512;

/// Room in the context for the prompt template the server wraps around the
/// request (d1-2B's is about 30 tokens), as `/tokenize` counts the request's
/// text only.
const TEMPLATE_TOKENS: usize = 64;

/// The local server's speed, and with it the longest call it can judge in
/// time (#178). A decision model reads the whole prompt in one batch, which
/// the server does not stop when the center gives up on it: a call too long
/// to read within the timeout would hold the server's one slot past it, and
/// every other session's call queued behind it would time out too (refused,
/// or let through unjudged with allow-and-log). So the client counts the
/// request's tokens first (`/tokenize`, which the server answers at once)
/// and does not send one it cannot read in time; that call is refused as
/// too long, also with allow-and-log, so padding a call does not get it past
/// the model.
#[derive(Debug)]
pub struct ReadBudget {
    /// The server's context, in tokens.
    context: usize,
    /// The milliseconds per token assumed until the server answered a call:
    /// the model's speed on 2 vCPUs (`install::ModelPin::read_ms`).
    assumed: f64,
    state: Mutex<Flights>,
}

/// How many recent speeds are kept: the slowest of them counts, so one fast
/// call on a quiet machine does not raise the budget for a busy one.
const SPEEDS_KEPT: usize = 8;

#[derive(Debug, Default)]
struct Flights {
    /// Milliseconds per token of the last calls that ran alone.
    speeds: VecDeque<f64>,
    in_flight: usize,
    /// Calls started so far, so a call can tell another one overlapped it.
    started: u64,
}

impl ReadBudget {
    pub fn new(context: u32, assumed_ms_per_token: f64) -> ReadBudget {
        ReadBudget {
            context: context as usize,
            assumed: assumed_ms_per_token,
            state: Mutex::default(),
        }
    }

    /// The context and the assumed speed it was built with.
    #[cfg(test)]
    pub(super) fn built_with(&self) -> (usize, f64) {
        (self.context, self.assumed)
    }

    /// Milliseconds per token: the slowest recent call's, or the assumed
    /// speed before the first.
    fn ms_per_token(&self) -> f64 {
        let s = self.state.lock().unwrap();
        s.speeds
            .iter()
            .copied()
            .reduce(f64::max)
            .unwrap_or(self.assumed)
    }

    /// Whether a request of `tokens` may be sent with `timeout_ms`.
    fn admit(&self, tokens: usize, timeout_ms: u64) -> Result<(), ModelError> {
        if tokens + TEMPLATE_TOKENS > self.context {
            return Err(ModelError::TooLong(format!(
                "about {tokens} tokens, more than the model's context of {} holds",
                self.context
            )));
        }
        if tokens <= ALWAYS_SENT_TOKENS {
            return Ok(());
        }
        let ms = tokens as f64 * self.ms_per_token();
        if ms <= timeout_ms as f64 {
            return Ok(());
        }
        Err(ModelError::TooLong(format!(
            "about {tokens} tokens, which the model reads here in about {:.0} s, longer than the timeout of {} ms",
            ms / 1000.0,
            timeout_ms
        )))
    }

    /// Marks a call as sent; its [`Flight`] takes its speed when it lands.
    fn take_off(&self) -> Flight<'_> {
        let mut s = self.state.lock().unwrap();
        let alone = s.in_flight == 0;
        s.in_flight += 1;
        s.started += 1;
        Flight {
            budget: self,
            alone,
            number: s.started,
        }
    }
}

/// A call on its way to the local server. Only a call that ran alone gives
/// a speed: one queued behind another (one slot) would count its wait.
struct Flight<'a> {
    budget: &'a ReadBudget,
    alone: bool,
    number: u64,
}

impl Flight<'_> {
    /// Takes the speed of a call of `tokens` that took `ms` (or, timed out,
    /// at least that long).
    fn land(&self, tokens: usize, ms: f64) {
        let mut s = self.budget.state.lock().unwrap();
        if self.alone && s.started == self.number && tokens > 0 {
            if s.speeds.len() == SPEEDS_KEPT {
                s.speeds.pop_front();
            }
            s.speeds.push_back(ms / tokens as f64);
        }
    }
}

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        self.budget.state.lock().unwrap().in_flight -= 1;
    }
}

/// Why a model call did not give an answer. Every one is a reason to refuse
/// (fail closed) unless the owner switched that off.
#[derive(Debug)]
pub enum ModelError {
    /// The model could not be reached (DNS, connection, TLS, timeout).
    Unreachable(String),
    /// It answered, but not with a usable decision (bad JSON, missing field,
    /// an HTTP error such as 401, 422, 429 or 529).
    Bad(String),
    /// The call was not sent: the local model cannot read it within the
    /// timeout, or its context does not hold it ([`ReadBudget`]). Refused
    /// whatever the owner chose for an unreachable model.
    TooLong(String),
}

impl std::fmt::Display for ModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModelError::Unreachable(e) => {
                write!(f, "the action checker's model cannot be reached: {e}")
            }
            ModelError::Bad(e) => {
                write!(f, "the action checker's model gave no usable answer: {e}")
            }
            ModelError::TooLong(e) => {
                write!(
                    f,
                    "the call is too long for the action checker's model: {e}"
                )
            }
        }
    }
}

/// The largest answer body the client reads.
const MAX_BODY: usize = 64 * 1024;

/// The largest `/tokenize` answer: a token id per byte of the longest
/// request at most, each a few digits.
const MAX_TOKENS_BODY: usize = 512 * 1024;

/// Asks the model whether the call described by `state` is dangerous, with the
/// question built from `cfg`. Returns the `noul` probability (0..=1).
pub async fn ask(endpoint: &Endpoint, cfg: &ModelConfig, state: Value) -> Result<f64, ModelError> {
    let mut body = json!({
        "state": state,
        "questions": {
            "danger": {
                "type": "noul",
                "instructions": cfg.instructions,
                "criteria": {"true": cfg.criteria_true, "false": cfg.criteria_false},
            }
        }
    });
    if let Some(m) = &endpoint.model {
        body["model"] = json!(m);
    }
    let timeout = Duration::from_millis(cfg.timeout_ms.max(100));
    let mut flight = None;
    if let Some(budget) = &endpoint.budget {
        let tokens = tokenize(endpoint, &body.to_string(), timeout).await?;
        budget.admit(tokens, cfg.timeout_ms)?;
        flight = Some((budget.take_off(), tokens));
    }
    let sent = Instant::now();
    let answer = tokio::time::timeout(
        timeout,
        request(endpoint, "/v1/systemone", &body, timeout, MAX_BODY),
    )
    .await;
    if let Some((flight, tokens)) = &flight {
        // A timed-out call took at least the timeout; that is its speed's
        // lower bound, so a machine slower than assumed is learned from it.
        if matches!(answer, Ok(Ok(_)) | Err(_)) {
            flight.land(*tokens, sent.elapsed().as_secs_f64() * 1000.0);
        }
    }
    let value = answer
        .map_err(|_| ModelError::Unreachable(format!("timed out after {} ms", cfg.timeout_ms)))??;
    parse_noul(&value)
}

/// The tokens of `text` as the decision server reads them, by the model's
/// own tokenizer (`POST /tokenize`).
///
/// `/tokenize` reads a special token's spelling in the text (`<|im_start|>`)
/// as one token by default, but the decision server does not let the call's
/// text hold special tokens: d1-2B's breaks each spelling with a zero-width
/// space, Kev-4B's rewrites `<|x|>` to `<¦x¦>`, and either is several plain
/// tokens. So the text is counted as plain text, and each `<` (every special
/// spelling of both models starts with one) counts one more token for the
/// break, which is at most one (measured for every spelling of both models,
/// review round 3 of #178). Otherwise a call padded with spellings counts as
/// a fraction of what the server reads, and gets past the budget.
async fn tokenize(endpoint: &Endpoint, text: &str, wait: Duration) -> Result<usize, ModelError> {
    let body = json!({ "content": text, "parse_special": false });
    let value = tokio::time::timeout(
        wait,
        request(endpoint, "/tokenize", &body, wait, MAX_TOKENS_BODY),
    )
    .await
    .map_err(|_| ModelError::Unreachable("counting the tokens timed out".into()))??;
    value
        .get("tokens")
        .and_then(Value::as_array)
        .map(|tokens| tokens.len() + text.matches('<').count())
        .ok_or_else(|| ModelError::Bad("/tokenize answered without tokens".into()))
}

/// Sends one request to `path` and returns its JSON body, mapping HTTP
/// errors.
async fn request(
    endpoint: &Endpoint,
    path: &str,
    body: &Value,
    wait: Duration,
    max_body: usize,
) -> Result<Value, ModelError> {
    let url = &endpoint.url;
    let proxy = if url.tls {
        nerve_transport::net::Proxy::from_env(&url.host).map_err(ModelError::Unreachable)?
    } else {
        None
    };
    let mut io = nerve_transport::net::open(url, None, proxy.as_ref())
        .await
        .map_err(ModelError::Unreachable)?;
    let path = format!("{}{path}", url.base);
    let req = request_bytes(&url.authority(), &path, endpoint.token.as_deref(), body);
    use tokio::io::AsyncWriteExt;
    io.write_all(req.as_bytes())
        .await
        .map_err(|e| ModelError::Unreachable(e.to_string()))?;
    // The model may think longer than the transport's usual head timeout (a
    // 4B model on a small CPU); the caller's own timeout around this call is
    // the limit, so this read does not cut it short at 15 s.
    let resp = nerve_transport::http::read_client_response(&mut io, max_body, wait)
        .await
        .map_err(ModelError::Unreachable)?;
    match resp.status {
        200 => serde_json::from_slice(&resp.body)
            .map_err(|e| ModelError::Bad(format!("not JSON: {e}"))),
        401 => Err(ModelError::Bad(
            "401: the model endpoint refused the token".into(),
        )),
        422 => Err(ModelError::Bad(
            "422: the model rejected the request".into(),
        )),
        429 => Err(ModelError::Bad(
            "429: the model endpoint is rate-limiting".into(),
        )),
        501 => Err(ModelError::Bad(
            "501: the loaded model is not a decision model (/v1/models has no \"decisions\")"
                .into(),
        )),
        529 => Err(ModelError::Bad(
            "529: the model endpoint is overloaded".into(),
        )),
        s => Err(ModelError::Bad(format!("HTTP {s}"))),
    }
}

/// The HTTP/1.1 request text, with the bearer token when there is one.
fn request_bytes(host: &str, path: &str, token: Option<&str>, body: &Value) -> String {
    let body = body.to_string();
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n{auth}Content-Length: {}\r\nConnection: close\r\nUser-Agent: nerve-center/{}\r\n\r\n{body}",
        body.len(),
        env!("CARGO_PKG_VERSION"),
    )
}

/// Pulls `answers.danger.noul` out of a System One response.
fn parse_noul(v: &Value) -> Result<f64, ModelError> {
    v.get("answers")
        .and_then(|a| a.get("danger"))
        .and_then(|d| d.get("noul"))
        .and_then(Value::as_f64)
        .filter(|p| p.is_finite() && (0.0..=1.0).contains(p))
        .ok_or_else(|| ModelError::Bad(format!("no noul answer in {v}")))
}

/// Reads `GET /v1/models` and reports whether the model is a decision model
/// (`architecture.output_modalities` contains `"decisions"`). Used before the
/// center trusts a local or endpoint model.
pub async fn is_decision_model(endpoint: &Endpoint) -> Result<bool, ModelError> {
    let url = &endpoint.url;
    let proxy = if url.tls {
        nerve_transport::net::Proxy::from_env(&url.host).map_err(ModelError::Unreachable)?
    } else {
        None
    };
    let mut io = nerve_transport::net::open(url, None, proxy.as_ref())
        .await
        .map_err(ModelError::Unreachable)?;
    let target = format!("{}/v1/models", url.base);
    let resp = nerve_transport::http::get(&mut io, &url.authority(), &target, MAX_BODY)
        .await
        .map_err(ModelError::Unreachable)?;
    if resp.status != 200 {
        return Err(ModelError::Bad(format!(
            "/v1/models answered HTTP {}",
            resp.status
        )));
    }
    let v: Value = serde_json::from_slice(&resp.body)
        .map_err(|e| ModelError::Bad(format!("/v1/models is not JSON: {e}")))?;
    let has = v
        .get("data")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|m| {
            m.get("architecture")
                .and_then(|a| a.get("output_modalities"))
                .and_then(Value::as_array)
                .is_some_and(|m| m.iter().any(|v| v.as_str() == Some("decisions")))
        });
    Ok(has)
}

/// A loopback stand-in for the local server, for tests: `/tokenize` counts
/// `tokens` for every plain text, `/v1/systemone` answers 0.01 after `delay`.
#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// The server's endpoint (without a budget) and how many decision
    /// requests it was sent.
    pub(crate) fn server(tokens: usize, delay: Duration) -> (Endpoint, Arc<AtomicUsize>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let asked = Arc::new(AtomicUsize::new(0));
        let counter = asked.clone();
        std::thread::spawn(move || {
            for mut c in listener.incoming().flatten() {
                let mut got = Vec::new();
                let mut buf = [0u8; 8192];
                // The request is small; read until its body is in.
                while let Ok(n) = c.read(&mut buf) {
                    got.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&got);
                    let done = text.split_once("\r\n\r\n").is_some_and(|(head, body)| {
                        let want = head
                            .lines()
                            .find_map(|l| l.strip_prefix("Content-Length: ")?.parse().ok())
                            .unwrap_or(0usize);
                        body.len() >= want
                    });
                    if n == 0 || done {
                        break;
                    }
                }
                let text = String::from_utf8_lossy(&got);
                let body = if text.starts_with("POST /tokenize ") {
                    // Like llama-server, it reads special spellings as one
                    // token each unless asked not to; here as one for the
                    // whole text.
                    let plain = text.contains(r#""parse_special":false"#);
                    json!({ "tokens": vec![1; if plain { tokens } else { 1 }] }).to_string()
                } else {
                    counter.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(delay);
                    r#"{"answers":{"danger":{"type":"noul","noul":0.01}}}"#.to_string()
                };
                let _ = write!(
                    c,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        let ep = Endpoint::parse(&format!("http://127.0.0.1:{port}"), None, None).unwrap();
        (ep, asked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    fn with_timeout(timeout_ms: u64) -> ModelConfig {
        ModelConfig {
            timeout_ms,
            ..Default::default()
        }
    }

    /// The local server is not sent a call it cannot read within the
    /// timeout (#178): before its first answer at the assumed speed, then at
    /// the slowest speed it measured. A call of up to 512 tokens is sent
    /// whatever the speed, and one over the context never.
    #[tokio::test]
    async fn a_call_the_local_model_cannot_read_in_time_is_not_sent() {
        let budget = Arc::new(ReadBudget::new(4096, 20.0));
        let local = |tokens| {
            let (ep, asked) = fake::server(tokens, Duration::ZERO);
            let ep = Endpoint {
                budget: Some(budget.clone()),
                ..ep
            };
            (ep, asked)
        };
        // 1,000 tokens at 20 ms each is 20 s, over the 12 s timeout.
        let (ep, asked) = local(1000);
        let e = ask(&ep, &with_timeout(12_000), json!({}))
            .await
            .unwrap_err();
        assert!(
            matches!(&e, ModelError::TooLong(why) if why.contains("about 20 s")),
            "{e}"
        );
        assert_eq!(asked.load(Ordering::SeqCst), 0);
        // 512 tokens at 20 ms are 10.2 s, over a 10 s timeout, and are sent
        // even so; this one is answered at once, so the speed measured is
        // well under 20 ms per token.
        let (ep, asked) = local(ALWAYS_SENT_TOKENS);
        assert_eq!(
            ask(&ep, &with_timeout(10_000), json!({})).await.unwrap(),
            0.01
        );
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        // Now the 1,000 tokens fit.
        let (ep, asked) = local(1000);
        assert_eq!(
            ask(&ep, &with_timeout(12_000), json!({})).await.unwrap(),
            0.01
        );
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        // A call over the context (with room for the template) is never
        // sent, however fast the model.
        let (ep, asked) = local(4096 - TEMPLATE_TOKENS + 1);
        let e = ask(&ep, &with_timeout(12_000), json!({}))
            .await
            .unwrap_err();
        assert!(
            matches!(&e, ModelError::TooLong(why) if why.contains("context")),
            "{e}"
        );
        assert_eq!(asked.load(Ordering::SeqCst), 0);
        // An endpoint has no budget: the center sends it everything.
        let (ep, asked) = fake::server(100_000, Duration::ZERO);
        assert_eq!(
            ask(&ep, &with_timeout(12_000), json!({})).await.unwrap(),
            0.01
        );
        assert_eq!(asked.load(Ordering::SeqCst), 1);
    }

    /// A call padded with special-token spellings is counted as the server
    /// reads it, where each spelling is broken into plain tokens, not as
    /// `/tokenize` counts it by default, one token per spelling (review
    /// round 3 of #178).
    #[tokio::test]
    async fn a_call_padded_with_special_spellings_is_counted_as_plain_text() {
        let budget = Arc::new(ReadBudget::new(4096, 20.0));
        let (ep, asked) = fake::server(300, Duration::ZERO);
        let ep = Endpoint {
            budget: Some(budget),
            ..ep
        };
        // 300 plain tokens and 300 spellings, one more token each for the
        // break: 600 at 20 ms are 12 s, over the 8 s timeout.
        let padded = "<|img_row_10_col_10|>".repeat(300);
        let e = ask(&ep, &with_timeout(8000), json!({ "target": padded }))
            .await
            .unwrap_err();
        assert!(
            matches!(&e, ModelError::TooLong(why) if why.contains("about 600 tokens")),
            "{e}"
        );
        assert_eq!(asked.load(Ordering::SeqCst), 0);
    }

    /// The slowest of the recent calls sets the speed, a timed-out call
    /// counts as at least its timeout, and a call that overlapped another
    /// one gives none (it may have waited for the server's one slot).
    #[test]
    fn the_budget_keeps_the_slowest_speed_of_the_calls_that_ran_alone() {
        let b = ReadBudget::new(8192, 20.0);
        assert_eq!(b.ms_per_token(), 20.0);
        b.take_off().land(1000, 5000.0);
        b.take_off().land(1000, 2000.0);
        assert_eq!(b.ms_per_token(), 5.0);
        assert!(b.admit(2000, 12_000).is_ok());
        assert!(b.admit(2500, 12_000).is_err());
        // Two at once: neither counts.
        let first = b.take_off();
        let second = b.take_off();
        second.land(100, 9000.0);
        first.land(100, 9000.0);
        drop((first, second));
        assert_eq!(b.ms_per_token(), 5.0);
        // A call that started while one was still in the air does not count
        // either, even after that one landed.
        let first = b.take_off();
        let second = b.take_off();
        first.land(100, 100.0);
        drop(first);
        second.land(100, 9000.0);
        drop(second);
        assert_eq!(b.ms_per_token(), 5.0);
        // Only the last few speeds are kept.
        for _ in 0..SPEEDS_KEPT {
            b.take_off().land(1000, 3000.0);
        }
        assert_eq!(b.ms_per_token(), 3.0);
    }

    /// A call that timed out took at least the timeout: the next long one is
    /// not sent at the speed assumed before (#178).
    #[tokio::test]
    async fn a_timed_out_call_slows_the_budget_down() {
        // 1,000 tokens at the assumed 0.5 ms are 500 ms, inside 600.
        let budget = Arc::new(ReadBudget::new(8192, 0.5));
        assert!(budget.admit(1000, 600).is_ok());
        let (ep, asked) = fake::server(1000, Duration::from_millis(1500));
        let ep = Endpoint {
            budget: Some(budget.clone()),
            ..ep
        };
        let e = ask(&ep, &with_timeout(600), json!({})).await.unwrap_err();
        assert!(matches!(e, ModelError::Unreachable(_)), "{e}");
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        assert!(budget.ms_per_token() >= 0.6, "{}", budget.ms_per_token());
        assert!(budget.admit(1000, 600).is_err());
    }

    /// A model that thinks longer than the transport's usual 15 s head
    /// timeout is still read when the checker's own timeout allows it (a
    /// 4B model, or a 2B one on a small VM CPU, can take that long). Found on the
    /// Windows test VM, where every call was cut at 15 s.
    #[tokio::test]
    async fn a_slow_model_is_waited_for_up_to_the_checkers_timeout() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut c, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let _ = c.read(&mut buf);
                std::thread::sleep(Duration::from_secs(16));
                let body = r#"{"answers":{"danger":{"type":"noul","noul":0.9}}}"#;
                let _ = write!(
                    c,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        let ep = Endpoint::parse(&format!("http://127.0.0.1:{port}"), None, None).unwrap();
        let cfg = ModelConfig {
            timeout_ms: 25_000,
            ..Default::default()
        };
        let score = ask(&ep, &cfg, json!({"command": "rm -rf /"}))
            .await
            .unwrap();
        assert_eq!(score, 0.9);
    }

    #[test]
    fn a_noul_answer_is_read() {
        let v = json!({"answers": {"danger": {"type": "noul", "noul": 0.93}}});
        assert_eq!(parse_noul(&v).unwrap(), 0.93);
    }

    #[test]
    fn a_missing_or_out_of_range_answer_is_bad() {
        assert!(parse_noul(&json!({"answers": {}})).is_err());
        assert!(parse_noul(&json!({"answers": {"danger": {"noul": 2.0}}})).is_err());
        assert!(parse_noul(&json!({"answers": {"danger": {"noul": "x"}}})).is_err());
    }

    #[test]
    fn the_request_carries_the_token_and_the_fixed_question() {
        let ep = Endpoint::parse(
            "https://h:9931",
            Some("secret".into()),
            Some("jev-latest".into()),
        )
        .unwrap();
        let body = json!({"state": {"command": "rm -rf /"}, "questions": {}});
        let text = request_bytes(
            &ep.url.authority(),
            "/v1/systemone",
            ep.token.as_deref(),
            &body,
        );
        assert!(text.contains("Authorization: Bearer secret"));
        assert!(text.contains("POST /v1/systemone HTTP/1.1"));
    }
}
