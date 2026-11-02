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
///
/// A token of a long prompt takes longer to read than one of a short prompt
/// (attention reads the whole prompt): d1-2B read 8,500 tokens at 1.5 times
/// a short call's time per token (review round 4). So the time is estimated
/// as a short call's time per token for `n * (1 + n / growth)` tokens, and a
/// call's speed is taken the same way.
#[derive(Debug)]
pub struct ReadBudget {
    /// The server's context, in tokens.
    context: usize,
    /// The milliseconds per token of a short call assumed until the server
    /// answered one: the model's speed on 2 vCPUs
    /// (`install::ModelPin::read_ms`).
    assumed: f64,
    /// The prompt length at which a token takes twice as long to read as in
    /// a short call (`install::ModelPin::read_growth`).
    growth: f64,
    state: Mutex<Flights>,
}

/// How many recent speeds are kept: the slowest of them counts, so one fast
/// call on a quiet machine does not raise the budget for a busy one.
const SPEEDS_KEPT: usize = 8;

#[derive(Debug, Default)]
struct Flights {
    /// Milliseconds per token of a short call, of the last calls that ran
    /// alone.
    speeds: VecDeque<f64>,
    in_flight: usize,
    /// Calls started so far, so a call can tell another one overlapped it.
    started: u64,
}

impl ReadBudget {
    pub fn new(context: u32, assumed_ms_per_token: f64, growth: f64) -> ReadBudget {
        ReadBudget {
            context: context as usize,
            assumed: assumed_ms_per_token,
            growth,
            state: Mutex::default(),
        }
    }

    /// The context, the assumed speed and the growth it was built with.
    #[cfg(test)]
    pub(super) fn built_with(&self) -> (usize, f64, f64) {
        (self.context, self.assumed, self.growth)
    }

    /// A prompt of `tokens`, in tokens of a short call's speed.
    fn work(&self, tokens: usize) -> f64 {
        let n = tokens as f64;
        n * (1.0 + n / self.growth)
    }

    /// Milliseconds per token of a short call: the slowest recent call's,
    /// or the assumed speed before the first.
    pub fn ms_per_token(&self) -> f64 {
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
        // The server reads the prompt template too.
        let ms = self.work(tokens + TEMPLATE_TOKENS) * self.ms_per_token();
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
    /// Takes the speed of a call whose prompt of `tokens` took `ms` (or,
    /// timed out, at least that long).
    fn land(&self, tokens: usize, ms: f64) {
        self.take(tokens, ms, false);
    }

    /// Like [`land`](Self::land) for a call that timed out. That speed is
    /// only a lower bound on the real one, and a call of up to 512 tokens
    /// was never checked against the timeout, so nothing else keeps it from
    /// being faster than the server: it never makes the budget faster, or a
    /// timeout the owner raised afterwards would turn it into a budget far
    /// above what the server reads (review round 5 of #178).
    fn land_timed_out(&self, tokens: usize, ms: f64) {
        self.take(tokens, ms, true);
    }

    fn take(&self, tokens: usize, ms: f64, timed_out: bool) {
        let work = self.budget.work(tokens);
        let mut s = self.budget.state.lock().unwrap();
        if self.alone && s.started == self.number && tokens > 0 {
            let mut speed = ms / work;
            if timed_out {
                let slowest = s.speeds.iter().copied().reduce(f64::max);
                speed = speed.max(slowest.unwrap_or(self.budget.assumed));
            }
            if s.speeds.len() == SPEEDS_KEPT {
                s.speeds.pop_front();
            }
            s.speeds.push_back(speed);
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
        let ms = sent.elapsed().as_secs_f64() * 1000.0;
        match &answer {
            // The speed comes from the tokens the server says it read, not
            // from the count above: that count is only an upper bound, and
            // a call padded so that it is counted several times what the
            // server reads (a run of `<`) would teach a speed several times
            // too fast, which lets a long call through afterwards (review
            // round 4 of #178). An answer that does not say teaches nothing.
            Ok(Ok(value)) => {
                if let Some(read) = read_tokens(value) {
                    flight.land(read, ms);
                }
            }
            // A timed-out call took at least the timeout for at most the
            // tokens counted (and the template); that is its speed's lower
            // bound, so a machine slower than assumed is learned from it.
            Err(_) => flight.land_timed_out(*tokens + TEMPLATE_TOKENS, ms),
            Ok(Err(_)) => {}
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

/// The tokens the server read for an answer (`usage.input_tokens`).
fn read_tokens(v: &Value) -> Option<usize> {
    v.get("usage")
        .and_then(|u| u.get("input_tokens"))
        .and_then(Value::as_u64)
        .map(|n| n as usize)
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
/// `tokens` for every plain text, `/v1/systemone` answers 0.01 after `delay`,
/// having read as many.
#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// The server's endpoint (without a budget) and how many decision
    /// requests it was sent.
    pub(crate) fn server(tokens: usize, delay: Duration) -> (Endpoint, Arc<AtomicUsize>) {
        server_reading(tokens, Some(tokens), delay)
    }

    /// The same, but its answers say it read `read` tokens (`None`: they do
    /// not say).
    pub(crate) fn server_reading(
        tokens: usize,
        read: Option<usize>,
        delay: Duration,
    ) -> (Endpoint, Arc<AtomicUsize>) {
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
                    let mut answer = json!({"answers": {"danger": {"type": "noul", "noul": 0.01}}});
                    if let Some(read) = read {
                        answer["usage"] = json!({ "input_tokens": read, "output_tokens": 0 });
                    }
                    answer.to_string()
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

    /// A budget whose calls take as long per token at any length, so the
    /// tests of everything else can count in plain sums.
    fn linear(context: u32, ms_per_token: f64) -> ReadBudget {
        ReadBudget::new(context, ms_per_token, f64::INFINITY)
    }

    /// The local server is not sent a call it cannot read within the
    /// timeout (#178): before its first answer at the assumed speed, then at
    /// the slowest speed it measured. A call of up to 512 tokens is sent
    /// whatever the speed, and one over the context never.
    #[tokio::test]
    async fn a_call_the_local_model_cannot_read_in_time_is_not_sent() {
        let budget = Arc::new(linear(4096, 20.0));
        let local = |tokens| {
            let (ep, asked) = fake::server(tokens, Duration::ZERO);
            let ep = Endpoint {
                budget: Some(budget.clone()),
                ..ep
            };
            (ep, asked)
        };
        // 1,000 tokens and the template's 64 at 20 ms each are 21 s, over
        // the 12 s timeout.
        let (ep, asked) = local(1000);
        let e = ask(&ep, &with_timeout(12_000), json!({}))
            .await
            .unwrap_err();
        assert!(
            matches!(&e, ModelError::TooLong(why) if why.contains("about 21 s")),
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
        let budget = Arc::new(linear(4096, 20.0));
        let (ep, asked) = fake::server(300, Duration::ZERO);
        let ep = Endpoint {
            budget: Some(budget),
            ..ep
        };
        // 300 plain tokens and 300 spellings, one more token each for the
        // break: 600 (and the template) at 20 ms are 13 s, over the 8 s
        // timeout.
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
        let b = linear(8192, 20.0);
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
        // 1,000 tokens and the template at the assumed 0.5 ms are 532 ms,
        // inside 600.
        let budget = Arc::new(linear(8192, 0.5));
        assert!(budget.admit(1000, 600).is_ok());
        let (ep, asked) = fake::server(1000, Duration::from_millis(1500));
        let ep = Endpoint {
            budget: Some(budget.clone()),
            ..ep
        };
        let e = ask(&ep, &with_timeout(600), json!({})).await.unwrap_err();
        assert!(matches!(e, ModelError::Unreachable(_)), "{e}");
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        assert!(budget.ms_per_token() >= 0.56, "{}", budget.ms_per_token());
        assert!(budget.admit(1000, 600).is_err());
    }

    /// Timed-out calls of up to 512 tokens were never checked against the
    /// timeout, so what they teach is only a lower bound: a short timeout
    /// must not leave a budget that a raised one turns into a stall (review
    /// round 5 of #178).
    #[tokio::test]
    async fn timed_out_short_calls_do_not_make_the_budget_faster() {
        // Assumed 20 ms per token; a 300-token call timing out at 100 ms
        // would land about 0.27 ms per token.
        let budget = Arc::new(linear(100_000, 20.0));
        let (ep, _) = fake::server(300, Duration::from_millis(1500));
        let ep = Endpoint {
            budget: Some(budget.clone()),
            ..ep
        };
        for _ in 0..8 {
            ask(&ep, &with_timeout(100), json!({})).await.unwrap_err();
        }
        assert!(budget.ms_per_token() >= 20.0, "{}", budget.ms_per_token());
        // 2,500 tokens take 50 s at 20 ms; a raised timeout of 12 s refuses.
        assert!(budget.admit(2500, 12_000).is_err());
    }

    /// The speed is learned from the tokens the server read, not from the
    /// count the call was let through with, which only bounds them: a call
    /// padded with plain `<` counts about four times what d1-2B reads, and
    /// such calls taught a speed fast enough to let a call through that held
    /// the server for a minute (review round 4 of #178). An answer that does
    /// not say what it read teaches nothing.
    #[tokio::test]
    async fn the_budget_learns_its_speed_from_the_tokens_the_server_read() {
        let budget = Arc::new(linear(100_000, 1.0));
        // Counted 2,000 tokens, read 500, in 250 ms: 0.5 ms per token read.
        let (ep, asked) = fake::server_reading(2000, Some(500), Duration::from_millis(250));
        let ep = Endpoint {
            budget: Some(budget.clone()),
            ..ep
        };
        ask(&ep, &with_timeout(5000), json!({})).await.unwrap();
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        assert!(budget.ms_per_token() >= 0.5, "{}", budget.ms_per_token());
        // 12,000 tokens at 0.5 ms are 6 s, over 5 s; at the 0.13 ms per
        // counted token they would have been 1.5 s.
        assert!(budget.admit(12_000, 5000).is_err());

        // An answer without the tokens read: the speed assumed stays.
        let budget = Arc::new(linear(100_000, 1.0));
        let (ep, asked) = fake::server_reading(2000, None, Duration::ZERO);
        let ep = Endpoint {
            budget: Some(budget.clone()),
            ..ep
        };
        ask(&ep, &with_timeout(5000), json!({})).await.unwrap();
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        assert_eq!(budget.ms_per_token(), 1.0);
    }

    /// A long call takes longer per token than the short calls the speed is
    /// learned from. With each model's pin, the measured long calls are
    /// refused at a timeout as long as they took, after the short call they
    /// followed (review round 4 of #178).
    #[test]
    fn a_long_call_is_held_to_the_slower_speed_of_its_length() {
        use crate::checker::config::LocalModel;
        use crate::checker::install::model_pin;
        // The model; the short call's tokens read and milliseconds; the long
        // call's tokens counted and milliseconds.
        let measured = [
            // Review round 4, 6 threads, the machine quiet: 240 tokens in
            // 1.15 s, then a call of control characters, the largest kind
            // of state, in 62.1 s.
            (LocalModel::D1_2b, 240, 1149.0, 8475, 62_100.0),
            // The evaluation's peak run (`raw/peak-d1-2b-c12288.server.log`),
            // 4 threads: 376 in 2.16 s, 8,070 read (about 8,045 counted) in
            // 59.9 s.
            (LocalModel::D1_2b, 376, 2159.0, 8045, 59_877.0),
            // Kev-4B's (`raw/peak-kev-4b-c8192.server.log`): 455 in 9.0 s,
            // 4,386 read in 134.9 s.
            (LocalModel::Kev4b, 455, 9043.0, 4361, 134_916.0),
        ];
        for (model, short, short_ms, long, long_ms) in measured {
            let pin = model_pin(model);
            let b = ReadBudget::new(pin.context, pin.read_ms, pin.read_growth);
            b.take_off().land(short, short_ms);
            assert!(
                b.admit(long, long_ms as u64).is_err(),
                "{model:?}: {long} tokens admitted in {long_ms} ms"
            );
        }
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
