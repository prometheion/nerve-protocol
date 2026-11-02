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

use std::time::Duration;

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
        })
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
        }
    }
}

/// The largest answer body the client reads.
const MAX_BODY: usize = 64 * 1024;

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
    let value = tokio::time::timeout(timeout, request(endpoint, &body, timeout))
        .await
        .map_err(|_| ModelError::Unreachable(format!("timed out after {} ms", cfg.timeout_ms)))??;
    parse_noul(&value)
}

/// Sends one request and returns its JSON body, mapping HTTP errors.
async fn request(endpoint: &Endpoint, body: &Value, wait: Duration) -> Result<Value, ModelError> {
    let url = &endpoint.url;
    let proxy = if url.tls {
        nerve_transport::net::Proxy::from_env(&url.host).map_err(ModelError::Unreachable)?
    } else {
        None
    };
    let mut io = nerve_transport::net::open(url, None, proxy.as_ref())
        .await
        .map_err(ModelError::Unreachable)?;
    let path = format!("{}/v1/systemone", url.base);
    let req = request_bytes(&url.authority(), &path, endpoint.token.as_deref(), body);
    use tokio::io::AsyncWriteExt;
    io.write_all(req.as_bytes())
        .await
        .map_err(|e| ModelError::Unreachable(e.to_string()))?;
    // The model may think longer than the transport's usual head timeout (a
    // 4B model on a small CPU); the caller's own timeout around this call is
    // the limit, so this read does not cut it short at 15 s.
    let resp = nerve_transport::http::read_client_response(&mut io, MAX_BODY, wait)
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

#[cfg(test)]
mod tests {
    use super::*;

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
