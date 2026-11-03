//! The center web UI: a small page (vanilla HTML/JS/CSS built into the
//! binary) over a JSON API.
//!
//! Access: the login is a harness token, the same secret the HTTP MCP
//! endpoint takes (one from the environment or a flag, or one made here and
//! kept hashed). Without a login the page is open to this machine only, and
//! the `Host` header must name loopback so a DNS-rebound page cannot reach
//! it. Beyond loopback a login is required and the UI is served over TLS (the
//! caller sees to both). The page and its assets are public: a navigation
//! carries no session, and nothing secret is in them. The login form posts
//! the token once and gets a session, which the page keeps in its tab and
//! sends as a header with every API call (nerve_transport::webui, no cookie);
//! `POST /logout` ends it. A session ends with its token: when the token is
//! deleted, the session stops working. A post must carry a matching
//! `Origin` when the browser sends one.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use nerve_proto::RpcError;
use nerve_transport::http::{self, Request, Response};
use nerve_transport::log::{Level, Query};
use nerve_transport::net::BoxIo;
use nerve_transport::webui::{self, Sessions, host_is_loopback, origin_matches, see_other};

use crate::center::{Center, Change, audit_rule};
use crate::listen::Server;
use crate::store::{PAIR_CODE_MAX_MINUTES, TokenRecord};
use crate::util::{self, now_ms};

const INDEX: &str = include_str!("ui/index.html");
const APP_JS: &str = include_str!("ui/app.js");

const WRONG_TOKEN: &str = "Wrong token.";
const TOO_MANY: &str = "Too many wrong tokens. Wait a minute and try again.";

const API_BODY: usize = 1024 * 1024;
/// Wrong tokens allowed per minute before logins pause.
const LOGIN_TRIES: u32 = 5;
/// How many log entries a view gets unless it asks for another number, and
/// the most it may ask for.
const LOG_PAGE: usize = 500;
const LOG_PAGE_MAX: usize = 1000;

pub struct Ui {
    center: Center,
    /// The token from the environment or a flag, besides the stored ones.
    env_token: Option<String>,
    login: bool,
    sessions: Sessions,
    failures: Mutex<(u32, Instant)>,
}

impl Ui {
    /// `login` is required unless the UI only listens on loopback.
    /// `env_token` is the harness token from the environment or a flag, if
    /// any.
    pub fn new(center: &Center, env_token: Option<String>, login: bool) -> Arc<Ui> {
        Arc::new(Ui {
            center: center.clone(),
            env_token: env_token.filter(|t| !t.is_empty()),
            login,
            sessions: Sessions::new(),
            failures: Mutex::new((0, Instant::now())),
        })
    }

    pub async fn serve(self: Arc<Self>, server: Server) {
        server
            .run(move |io, _| {
                let me = self.clone();
                async move { me.conn(io).await }
            })
            .await
    }

    async fn conn(&self, mut io: BoxIo) {
        let (resp, api) = match http::read_request(&mut io, API_BODY).await {
            Ok(req) => {
                let api = webui::is_api(&req.path);
                (self.request(req).await, api)
            }
            Err(_) => (Response::text(400, "bad request"), false),
        };
        let _ = webui::with_security_headers(resp, api).write(&mut io).await;
    }

    /// Answers one request.
    pub async fn request(&self, req: Request) -> Response {
        if !self.login && !host_is_loopback(req.header("host")) {
            return Response::text(403, "this UI answers only to a loopback host name");
        }
        // The page and what it loads are public: a navigation carries no
        // session, and the page asks /api/session first.
        if req.method == "GET" {
            if let Some(r) = webui::asset(&req.path) {
                return r;
            }
            match req.path.as_str() {
                "/" | "/index.html" => {
                    return Response::new(200, "text/html; charset=utf-8", INDEX);
                }
                "/app.js" => return Response::new(200, "text/javascript; charset=utf-8", APP_JS),
                _ => {}
            }
        }
        if req.method == "POST"
            && let Some(o) = req.header("origin")
            && !origin_matches(o, req.header("host"))
        {
            return Response::text(403, "cross-origin requests are refused");
        }
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/login") => return self.login_page(),
            ("POST", "/login") => return self.login(&req).await,
            ("POST", "/logout") => return self.logout(&req),
            ("GET", "/api/session") => return self.session_info(&req),
            _ => {}
        }
        if !webui::is_api(&req.path) {
            return Response::text(404, "not found");
        }
        if self.session_of(&req).is_none() {
            return Response::json(401, &json!({"error": "log in first"}));
        }
        if req.method == "GET" && req.path == "/api/log/download" {
            return self.log_download();
        }
        let body: Value = if req.body.is_empty() {
            json!({})
        } else {
            match serde_json::from_slice(&req.body) {
                Ok(v) => v,
                Err(e) => return Response::json(400, &json!({"error": format!("bad JSON: {e}")})),
            }
        };
        match self.api(&req, &body).await {
            Ok(v) => Response::json(200, &v),
            Err((status, v)) => Response::json(status, &v),
        }
    }

    /// The session `req`'s header names, while the token that opened it is
    /// still one.
    fn session_of(&self, req: &Request) -> Option<String> {
        let (token, session) = self.sessions.of(req)?;
        // Checked with the sessions unlocked: the check reads the center's
        // state, and a request that waits for it holds up no other.
        if let Some(h) = session.via
            && !crate::mcp::token_hash_ok(&self.center, self.env_token.as_deref(), &h)
        {
            self.sessions.end(&token);
            return None;
        }
        Some(token)
    }

    fn session_info(&self, req: &Request) -> Response {
        if self.session_of(req).is_some() {
            return Response::json(200, &json!({"login": self.login, "logged_in": true}));
        }
        if self.login {
            return Response::json(200, &json!({"login": true, "logged_in": false}));
        }
        // Open on loopback: a session is handed out, so that every API call
        // still comes from a page that asked here.
        let token = self.sessions.start(None);
        Response::json(
            200,
            &json!({"login": false, "logged_in": true, "session": token}),
        )
    }

    /// The login form, or the page itself when there is nothing to log in to.
    fn login_page(&self) -> Response {
        if !self.login {
            return see_other("/");
        }
        webui::login_page("Harness token", "One center for all your machines.")
    }

    /// Checks the token the login form posted. The answer is the session for
    /// the page to keep, or the reason it was refused; the token never
    /// appears in a URL or a log.
    async fn login(&self, req: &Request) -> Response {
        if !self.login {
            return see_other("/");
        }
        {
            let mut f = self.failures.lock().unwrap();
            if f.1.elapsed() > Duration::from_secs(60) {
                *f = (0, Instant::now());
            }
            if f.0 >= LOGIN_TRIES {
                return Response::json(429, &json!({"error": TOO_MANY}))
                    .with_header("Retry-After", "60");
            }
        }
        let log = self.center.log();
        let given = webui::posted_secret(req);
        if given.is_empty()
            || !crate::mcp::token_ok(&self.center, self.env_token.as_deref(), &given)
        {
            let tries = {
                let mut f = self.failures.lock().unwrap();
                f.0 += 1;
                f.0
            };
            // The token that was tried is not logged: a typo of a good one is
            // as good as the token.
            log.record(
                Level::Warn,
                None,
                "a web UI sign-in was refused: wrong token",
            );
            if tries >= LOGIN_TRIES {
                log.record(
                    Level::Warn,
                    None,
                    "the web UI sign-in is locked for a minute after too many wrong tokens",
                );
            }
            tokio::time::sleep(webui::WRONG_SECRET_DELAY).await;
            return Response::json(401, &json!({"error": WRONG_TOKEN}));
        }
        let token = self
            .sessions
            .start(Some(util::sha256_hex(given.as_bytes())));
        log.record(Level::Info, None, "signed in to the web UI");
        Response::json(200, &json!({"session": token}))
    }

    /// The log file for the owner to keep: both files, the older first, one
    /// JSON object per line.
    fn log_download(&self) -> Response {
        match self.center.log().file_bytes() {
            None => Response::json(404, &json!({"error": "this center keeps no log file"})),
            Some(Err(e)) => Response::json(
                500,
                &json!({"error": format!("cannot read the log file: {e}")}),
            ),
            Some(Ok(bytes)) => Response::new(200, "application/x-ndjson", bytes).with_header(
                "Content-Disposition",
                "attachment; filename=\"nerve-center-log.jsonl\"",
            ),
        }
    }

    /// Ends the session the request names; the page forgets it.
    fn logout(&self, req: &Request) -> Response {
        if let Some(t) = self.session_of(req) {
            self.sessions.end(&t);
        }
        Response::json(200, &json!({}))
    }

    async fn api(&self, req: &Request, b: &Value) -> Result<Value, (u16, Value)> {
        let c = &self.center;
        let s = |k: &str| b.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/api/overview") => Ok(json!({
                "center": {"id": c.id(), "name": c.name(), "url": c.public_url().to_string(), "pin": c.pin()},
                "nodes": c.nodes_json(),
                "alerts": c.alerts(),
                "sessions": c.sessions_json(),
            })),
            ("GET", "/api/stats") => Ok(c.stats_json()),
            ("GET", "/api/audit") => Ok(json!({"decisions": c.audit()})),
            ("GET", "/api/log") => Ok(c.log_json(&log_query(req)?)),
            // The node's own command list, read from its CLI definition.
            ("GET", "/api/help") => Ok(json!({"node": nerve_node::cli::help()})),
            ("POST", "/api/pair") => Ok(c.new_pairing()),
            ("POST", "/api/pair/status") => Ok(c.pairing_status(&s("code"))),
            ("POST", "/api/nodes/rename") => c
                .rename(&s("id"), &s("name"))
                .map(|_| json!({}))
                .map_err(bad),
            ("POST", "/api/nodes/disable") => {
                let Some(disabled) = b.get("disabled").and_then(Value::as_bool) else {
                    return Err(bad("disabled must be true or false"));
                };
                c.set_disabled(&s("id"), disabled)
                    .map(|_| json!({"disabled": disabled}))
                    .map_err(|e| (404, json!({"error": e})))
            }
            ("POST", "/api/nodes/remove") => {
                c.remove(&s("id")).await.map(|_| json!({})).map_err(bad)
            }
            ("POST", "/api/sessions/end") => {
                if c.end_session(&s("id")).await {
                    Ok(json!({}))
                } else {
                    Err(bad("no such session"))
                }
            }
            ("GET", "/api/nodes/settings") => {
                let id = req.query_param("id").unwrap_or_default();
                c.node_settings(&id).await.map_err(refused)
            }
            ("POST", "/api/nodes/settings") => c
                .set_node_settings(
                    &s("id"),
                    b.get("document").cloned().unwrap_or(Value::Null),
                    b.get("if_version").cloned().unwrap_or(Value::Null),
                )
                .await
                .map_err(refused),
            ("POST", "/api/nodes/sudo/offer") => c.node_sudo_offer(&s("id")).await.map_err(refused),
            ("POST", "/api/nodes/sudo") => c
                .set_node_sudo(
                    &s("id"),
                    b.get("on").and_then(Value::as_bool).unwrap_or(false),
                    b.get("sealed").cloned().filter(|v| !v.is_null()),
                )
                .await
                .map_err(refused),
            // ---- Capabilities ----
            ("GET", "/api/caps") => {
                let id = req.query_param("id").unwrap_or_default();
                c.node_caps(&id)
                    .await
                    .map_err(|e| (404, json!({"error": e})))
            }
            // The form, checked as the node checks a capability of its
            // config: what is wrong with each field, "" where nothing is.
            ("POST", "/api/caps/check") => {
                let form = cap_form(b)?;
                let errors = nerve_policy::config::form::check(&form, CAP_TIMEOUT_MAX);
                Ok(json!({"ok": errors.none(), "errors": errors}))
            }
            ("POST", "/api/caps/save") => {
                let form = cap_form(b)?;
                let adding = b.get("adding").and_then(Value::as_bool) == Some(true);
                let cap = nerve_policy::config::form::capability(&form, CAP_TIMEOUT_MAX)
                    .map_err(|e| (400, json!({"error": e.first(), "errors": e})))?;
                c.save_cap(&s("id"), &cap, adding).await.map_err(refused)
            }
            ("POST", "/api/caps/remove") => {
                c.remove_cap(&s("id"), &s("name")).await.map_err(refused)
            }
            // The four buttons of an audit entry: `list` is allow, deny, or
            // sudo for a sudo command; `cap`, `action` and `target` are the
            // entry's own fields.
            ("POST", "/api/audit/rule") => {
                let wildcard = b.get("wildcard").and_then(Value::as_bool) == Some(true);
                let pin = pin_of(b)?;
                let pin = pin.as_ref().map(|(f, v)| (f.as_str(), v));
                let rule = audit_rule(
                    &s("list"),
                    &s("cap"),
                    &s("action"),
                    &s("target"),
                    wildcard,
                    pin,
                )
                .map_err(bad)?;
                c.add_rule(&s("node_id"), &s("list"), &rule)
                    .await
                    .map(|v| json!({"rule": rule, "result": v}))
                    .map_err(refused)
            }
            // ---- Action checker (issue #17) ----
            ("GET", "/api/checker") => Ok(c.checker_json()),
            ("POST", "/api/checker") => {
                let cfg = serde_json::from_value(b.get("config").cloned().unwrap_or(Value::Null))
                    .map_err(|e| bad(format!("the checker settings are not valid: {e}")))?;
                c.apply_checker_config(cfg).map(|_| json!({})).map_err(bad)
            }
            ("POST", "/api/checker/token") => {
                let token = b.get("token").and_then(Value::as_str);
                c.set_checker_token(token).map(|_| json!({})).map_err(bad)
            }
            ("POST", "/api/checker/install") => {
                let gpu = b.get("gpu").and_then(Value::as_bool) == Some(true);
                let model = match b.get("model") {
                    None | Some(Value::Null) => c.read(|st| st.checker.model.local_model),
                    Some(v) => serde_json::from_value(v.clone())
                        .map_err(|_| bad("the model is d1-2b or kev-4b"))?,
                };
                c.start_checker_install(gpu, model)
                    .await
                    .map(|_| json!({}))
                    .map_err(bad)
            }
            ("POST", "/api/checker/remove") => c
                .remove_checker_model()
                .await
                .map(|_| json!({}))
                .map_err(bad),
            // The allow buttons on a checker refusal: build the rule for the
            // entry and save it for every node, or for the one node.
            ("POST", "/api/checker/allow") => {
                let wildcard = b.get("wildcard").and_then(Value::as_bool) == Some(true);
                let node = b
                    .get("node_id")
                    .and_then(Value::as_str)
                    .filter(|n| !n.is_empty())
                    .map(str::to_string);
                let pin = pin_of(b)?;
                let pin = pin.as_ref().map(|(f, v)| (f.as_str(), v));
                c.add_checker_allow(&s("cap"), &s("action"), &s("target"), wildcard, pin, node)
                    .map(|rule| json!({"rule": rule}))
                    .map_err(bad)
            }
            ("GET", "/api/tokens") => Ok(c.read(|st| {
                json!(
                    st.harness_tokens
                        .iter()
                        .map(|t| json!({"id": t.id, "label": t.label, "created_ms": t.created_ms}))
                        .collect::<Vec<_>>()
                )
            })),
            ("POST", "/api/tokens/create") => {
                let label = util::clip(s("label").trim(), 60);
                let token = format!("nrv_{}", nerve_transport::keys::random_token(40));
                let rec = TokenRecord {
                    id: nerve_transport::keys::random_token(12),
                    label: if label.is_empty() {
                        "harness".into()
                    } else {
                        label
                    },
                    hash: util::sha256_hex(token.as_bytes()),
                    created_ms: now_ms(),
                };
                let (id, label) = (rec.id.clone(), rec.label.clone());
                c.update(|st| st.harness_tokens.push(rec));
                c.log().record(
                    Level::Info,
                    None,
                    &format!("a harness token was made, labelled {label:?}"),
                );
                // The token is shown once; only its hash is kept.
                Ok(json!({"id": id, "token": token}))
            }
            ("POST", "/api/tokens/delete") => {
                let id = s("id");
                let gone = c.update(|st| {
                    let label = st
                        .harness_tokens
                        .iter()
                        .find(|t| t.id == id)
                        .map(|t| t.label.clone());
                    st.harness_tokens.retain(|t| t.id != id);
                    label
                });
                if let Some(label) = gone {
                    c.log().record(
                        Level::Info,
                        None,
                        &format!("the harness token labelled {label:?} was deleted"),
                    );
                }
                Ok(json!({}))
            }
            // The center's key (docs/dev/spec/protocol.md §4.10): the answer
            // to a rotation is the only place the new pin is shown.
            ("POST", "/api/center/key/rotate") => c.rotate_key().await.map_err(bad),
            ("POST", "/api/center/key/finish") => c
                .finish_key_rotation("the owner ended its grace")
                .await
                .map_err(bad),
            ("GET", "/api/center") => Ok(c.read(|st| {
                json!({
                    "name": st.center_name,
                    "retention_days": st.retention_days,
                    "pair_code_minutes": st.pair_code_minutes,
                    // The stored level is the setting; `--log` can hold another
                    // for this run (`log_level_now`).
                    "log_level": st.log_level,
                    "log_level_now": c.log().level(),
                    "log_level_pinned": c.log_level_pinned(),
                })
            }))
            .map(|mut v| {
                v["key"] = c.key_json();
                v
            }),
            ("POST", "/api/center") => {
                let name = b
                    .get("name")
                    .and_then(Value::as_str)
                    .map(|n| n.trim().to_string());
                if name.as_ref().is_some_and(|n| n.is_empty() || n.len() > 64) {
                    return Err(bad("a center name is 1 to 64 characters"));
                }
                let days = b.get("retention_days").and_then(Value::as_u64);
                if days.is_some_and(|d| !(1..=366).contains(&d)) {
                    return Err(bad("retention is 1 to 366 days"));
                }
                // A value that is not a whole number is refused too, not skipped.
                let minutes = match b.get("pair_code_minutes") {
                    None | Some(Value::Null) => None,
                    Some(v) => match v.as_u64() {
                        Some(m) if (1..=u64::from(PAIR_CODE_MAX_MINUTES)).contains(&m) => Some(m),
                        _ => {
                            return Err(bad(format!(
                                "a pairing code is valid for 1 to {PAIR_CODE_MAX_MINUTES} minutes (24 hours)"
                            )));
                        }
                    },
                };
                let level = match b.get("log_level") {
                    None | Some(Value::Null) => None,
                    Some(v) => match v.as_str().and_then(Level::parse) {
                        Some(l) => Some(l),
                        None => return Err(bad("the log level is error, warn, info or debug")),
                    },
                };
                let (old_name, old_days, old_minutes) = c.read(|st| {
                    (
                        st.center_name.clone(),
                        u64::from(st.retention_days),
                        u64::from(st.pair_code_minutes),
                    )
                });
                let mut changed = Vec::new();
                if name.as_ref().is_some_and(|n| *n != old_name) {
                    changed.push("name");
                }
                if days.is_some_and(|d| d != old_days) {
                    changed.push("statistics retention");
                }
                if minutes.is_some_and(|m| m != old_minutes) {
                    changed.push("pairing code lifetime");
                }
                c.update(|st| {
                    if let Some(n) = name {
                        st.center_name = n;
                    }
                    if let Some(d) = days {
                        st.retention_days = d as u32;
                    }
                    if let Some(m) = minutes {
                        st.pair_code_minutes = m as u32;
                    }
                });
                if let Some(l) = level {
                    c.set_log_level(l);
                }
                // The UI sends all its fields every time, so only what differs
                // is told.
                if !changed.is_empty() {
                    c.log().record(
                        Level::Info,
                        None,
                        &format!("the center settings were saved ({})", changed.join(", ")),
                    );
                }
                c.changed(Change::Nodes);
                Ok(json!({}))
            }
            _ => Err((404, json!({"error": "unknown API call"}))),
        }
    }
}

/// The log view's question, from the query string: `level` (the least severe
/// to show), `node` (an id, or `-` for the center alone), `q` (text),
/// `after` (an entry number) and `limit`.
fn log_query(req: &Request) -> Result<Query, (u16, Value)> {
    let level = match req.query_param("level").filter(|l| !l.is_empty()) {
        None => None,
        Some(l) => {
            Some(Level::parse(&l).ok_or_else(|| bad("the level is error, warn, info or debug"))?)
        }
    };
    let number = |k: &str| -> Result<Option<u64>, (u16, Value)> {
        match req.query_param(k).filter(|v| !v.is_empty()) {
            None => Ok(None),
            Some(v) => v
                .parse()
                .map(Some)
                .map_err(|_| bad(format!("{k} is a whole number"))),
        }
    };
    Ok(Query {
        level,
        node: req.query_param("node").filter(|n| !n.is_empty()),
        text: req.query_param("q"),
        after: number("after")?,
        limit: number("limit")?.map_or(LOG_PAGE, |n| (n as usize).clamp(1, LOG_PAGE_MAX)),
    })
}

fn bad(m: impl Into<String>) -> (u16, Value) {
    (400, json!({"error": m.into()}))
}

/// The argument an audit button pins, from the request's `pin`
/// (`{"field": "room", "value": "office"}`), the value as the entry has it.
fn pin_of(b: &Value) -> Result<Option<(String, Value)>, (u16, Value)> {
    match b.get("pin") {
        None | Some(Value::Null) => Ok(None),
        Some(p) => {
            let field = p.get("field").and_then(Value::as_str);
            match (field, p.get("value")) {
                (Some(f), Some(v)) => Ok(Some((f.to_string(), v.clone()))),
                _ => Err(bad("a pin is {field, value}")),
            }
        }
    }
}

/// The time limit the center's check of a capability allows: the node
/// knows its own `limits.max_timeout_secs` and checks it when it saves.
const CAP_TIMEOUT_MAX: u64 = u64::MAX;

/// The form of the Capabilities tab in a request's `form`.
fn cap_form(b: &Value) -> Result<nerve_policy::config::form::CapForm, (u16, Value)> {
    serde_json::from_value(b.get("form").cloned().unwrap_or(Value::Null))
        .map_err(|e| bad(format!("the form is not valid: {e}")))
}

/// A node's refusal, with its code and reason, for the UI to show.
fn refused(e: RpcError) -> (u16, Value) {
    (
        409,
        json!({"error": e.message, "code": e.kind().as_str(), "data": e.data}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use nerve_transport::webui::{APP_CSS, KIT_JS};
    use std::collections::BTreeMap;

    fn req(method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Request {
        let mut h = BTreeMap::new();
        for (k, v) in headers {
            h.insert(k.to_ascii_lowercase(), v.to_string());
        }
        Request {
            method: method.into(),
            path: path.into(),
            query: String::new(),
            headers: h,
            body: body.as_bytes().to_vec(),
        }
    }

    fn center(dir: &std::path::Path) -> Center {
        nerve_transport::init_crypto();
        Center::open(crate::center::Options {
            state_dir: dir.to_path_buf(),
            name: Some("test".into()),
            public_url: "http://127.0.0.1:1".into(),
            log: None,
            log_level: None,
        })
        .unwrap()
    }

    /// The header a page sends its session in.
    const SESSION: &str = "X-Nerve-Session";

    /// The session an answer of `/api/session` or `/login` hands out.
    fn session_token(r: &Response) -> String {
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        v["session"].as_str().expect("a session").to_string()
    }

    /// Every command and sub-command of the node CLI, by the words after
    /// `nerve-node`, with its explanation, read straight from clap's tree.
    fn node_commands(cmd: &clap::Command, prefix: &str, out: &mut Vec<(String, String)>) {
        for sub in cmd.get_subcommands() {
            if sub.get_name() == "help" {
                continue;
            }
            let name = format!("{prefix}{}", sub.get_name());
            let about = sub.get_about().map(ToString::to_string).unwrap_or_default();
            node_commands(sub, &format!("{name} "), out);
            out.push((name, about));
        }
    }

    #[tokio::test]
    async fn the_pairing_card_offers_the_command_and_the_bare_link() {
        let d = tempfile::tempdir().unwrap();
        let ui = Ui::new(&center(d.path()), None, false);
        let h = ("Host", "127.0.0.1:7480");
        let session = ui.request(req("GET", "/api/session", &[h], "")).await;
        let ck = session_token(&session);
        let js = ui
            .request(req("GET", "/app.js", &[h, (SESSION, &ck)], ""))
            .await;
        let js = String::from_utf8(js.body).unwrap();
        let card = &js[js.find("function pairingCard").unwrap()..];
        let card = &card[..card.find("\n}\n").unwrap()];
        // Two rows with a Copy each: the command, and the link alone for the
        // desktop app. The link's parts are not shown apart.
        assert!(card.contains("row(\"Command\", command)"), "{card}");
        assert!(card.contains("row(\"Link\", p.link)"), "{card}");
        for gone in ["\"Center\"", "\"Code\"", "\"Certificate pin\""] {
            assert!(!card.contains(gone), "{gone} is still a row: {card}");
        }
    }

    #[tokio::test]
    async fn the_help_page_lists_every_node_command() {
        use clap::CommandFactory;
        let d = tempfile::tempdir().unwrap();
        let ui = Ui::new(&center(d.path()), None, false);
        let h = ("Host", "127.0.0.1:7480");
        let session = ui.request(req("GET", "/api/session", &[h], "")).await;
        let ck = session_token(&session);
        // The page: a tab in the menu, drawn from /api/help.
        let index = ui.request(req("GET", "/", &[h, (SESSION, &ck)], "")).await;
        let index = String::from_utf8(index.body).unwrap();
        assert!(index.contains("href=\"#help\""), "no Help tab in the menu");
        let js = ui
            .request(req("GET", "/app.js", &[h, (SESSION, &ck)], ""))
            .await;
        let js = String::from_utf8(js.body).unwrap();
        assert!(js.contains("\"/api/help\"") && js.contains("pageHelp"));
        // The data: every command of the CLI definition, with its words, on
        // cards in sections. A noun's own command is in its card's `holds`.
        let r = ui
            .request(req("GET", "/api/help", &[h, (SESSION, &ck)], ""))
            .await;
        assert_eq!(r.status, 200);
        let body: Value = serde_json::from_slice(&r.body).unwrap();
        let mut listed: Vec<(String, String)> = Vec::new();
        for s in body["node"]["sections"].as_array().unwrap() {
            assert!(!s["about"].as_str().unwrap().is_empty());
            for c in s["cards"].as_array().unwrap() {
                for held in c["holds"].as_array().unwrap() {
                    // Its sentence is the card's.
                    let held = held.as_str().unwrap().to_string();
                    let about = if c["name"] == held.as_str() {
                        c["about"].as_str().unwrap().to_string()
                    } else {
                        String::new()
                    };
                    listed.push((held, about));
                }
                for v in c["verbs"].as_array().unwrap() {
                    listed.push((
                        v["name"].as_str().unwrap().to_string(),
                        v["about"].as_str().unwrap().to_string(),
                    ));
                }
            }
        }
        let mut cli = Vec::new();
        node_commands(&nerve_node::cli::Cli::command(), "", &mut cli);
        assert!(cli.len() > 40, "{cli:?}");
        for (name, about) in &cli {
            assert!(!about.is_empty(), "`{name}` has no explanation");
            assert!(
                listed.contains(&(name.clone(), about.clone())),
                "`{name}` is not on the help page: {listed:?}"
            );
        }
        assert_eq!(listed.len(), cli.len());
        // The help is for a signed-in browser like every other API.
        let ui = Ui::new(&center(d.path()), Some("nrv_x".into()), true);
        let r = ui.request(req("GET", "/api/help", &[h], "")).await;
        assert_eq!(r.status, 401);
    }

    async fn pair_status(ui: &Ui, code: &str) -> Value {
        ui.api(
            &req("POST", "/api/pair/status", &[], ""),
            &json!({"code": code}),
        )
        .await
        .unwrap()
    }

    async fn new_code(ui: &Ui) -> String {
        let made = ui
            .api(&req("POST", "/api/pair", &[], ""), &json!({}))
            .await
            .unwrap();
        made["code"].as_str().unwrap().to_string()
    }

    fn pair_body(code: &str, name: &str, key: u8) -> Vec<u8> {
        json!({
            "code": code, "name": name, "platform": "linux", "arch": "x86_64",
            "public_key": nerve_proto::msg::hex(&[key; 32]),
        })
        .to_string()
        .into_bytes()
    }

    #[tokio::test]
    async fn the_pairing_status_says_when_a_code_is_used_up() {
        let d = tempfile::tempdir().unwrap();
        let c = center(d.path());
        let ui = Ui::new(&c, None, false);
        let code = new_code(&ui).await;
        assert_eq!(pair_status(&ui, &code).await["open"], true);
        // Asking, even with wrong codes, uses up nothing.
        for _ in 0..crate::pairing::TRIES {
            assert_eq!(pair_status(&ui, "wrong").await["open"], false);
        }
        assert_eq!(pair_status(&ui, &code).await["open"], true);
        // A machine pairs with the code: the page sees it is gone, and which
        // machine it paired.
        assert_eq!(c.pair(&pair_body(&code, "box-1", 7)).0, 200);
        let st = pair_status(&ui, &code).await;
        assert_eq!(st["open"], false);
        assert_eq!(st["node"]["name"], "box-1");
    }

    #[tokio::test]
    async fn a_code_names_only_the_machine_it_paired() {
        let d = tempfile::tempdir().unwrap();
        let c = center(d.path());
        let ui = Ui::new(&c, None, false);
        // Two cards open (two tabs): another code pairs a machine.
        let mine = new_code(&ui).await;
        let other = new_code(&ui).await;
        assert_eq!(c.pair(&pair_body(&other, "box-2", 8)).0, 200);
        let st = pair_status(&ui, &mine).await;
        assert_eq!(
            (st["open"].as_bool(), st["node"].is_null()),
            (Some(true), true)
        );
        // Mine runs out of tries: closed, and no machine named, as box-2 is
        // not the one this code paired.
        for _ in 0..crate::pairing::TRIES {
            assert_eq!(c.pair(&pair_body("wrongwrong12", "box-3", 9)).0, 403);
        }
        let st = pair_status(&ui, &mine).await;
        assert_eq!(
            (st["open"].as_bool(), st["node"].is_null()),
            (Some(false), true)
        );
        assert_eq!(pair_status(&ui, &other).await["node"]["name"], "box-2");
    }

    #[tokio::test]
    async fn a_pairing_that_is_refused_leaves_its_code_open() {
        let d = tempfile::tempdir().unwrap();
        let c = center(d.path());
        let ui = Ui::new(&c, None, false);
        let first = new_code(&ui).await;
        assert_eq!(c.pair(&pair_body(&first, "box-1", 7)).0, 200);
        // The same key again with a new code: refused with 409. The page
        // must not take that code for used.
        let second = new_code(&ui).await;
        assert_eq!(c.pair(&pair_body(&second, "box-2", 7)).0, 409);
        let st = pair_status(&ui, &second).await;
        assert_eq!(
            (st["open"].as_bool(), st["node"].is_null()),
            (Some(true), true)
        );
        // Refused is not "in progress": with its tries gone it reads closed.
        for _ in 0..crate::pairing::TRIES {
            assert_eq!(c.pair(&pair_body("wrongwrong12", "box-3", 9)).0, 403);
        }
        let st = pair_status(&ui, &second).await;
        assert_eq!(
            (st["open"].as_bool(), st["node"].is_null()),
            (Some(false), true)
        );
    }

    #[tokio::test]
    async fn the_page_closes_the_pairing_card_when_the_code_is_used() {
        let d = tempfile::tempdir().unwrap();
        let ui = Ui::new(&center(d.path()), None, false);
        let h = ("Host", "127.0.0.1:7480");
        let session = ui.request(req("GET", "/api/session", &[h], "")).await;
        let ck = session_token(&session);
        let js = ui
            .request(req("GET", "/app.js", &[h, (SESSION, &ck)], ""))
            .await;
        let js = String::from_utf8(js.body).unwrap();
        // The poll asks the center about the code on screen and drops the
        // card when it is gone.
        let ask = js.find("\"/api/pair/status\"").expect("the page asks");
        let poll = js.find("async function tick()").unwrap();
        let tick_end = js[poll..].find("\n}\n").unwrap() + poll;
        assert!(js[poll..tick_end].contains("closePairingWhenUsed("));
        // It names the machine the center says, not one found in the list.
        assert!(js[ask..poll].contains("node.name") && !js.contains(".known"));
        assert!(js[..ask].contains("function closePairingWhenUsed"));
        assert!(js[ask..poll].contains("state.pairing = null"));
    }

    #[tokio::test]
    async fn the_statistics_page_has_a_picker_and_the_numbers_it_picks_from() {
        use crate::store::{CallStats, NodeRecord, Store};
        let d = tempfile::tempdir().unwrap();
        let mut store = Store::new("c".into(), "home".into());
        for (id, name, count) in [("n1", "alpha", 3), ("n2", "beta", 4)] {
            store.nodes.insert(
                id.into(),
                NodeRecord {
                    id: id.into(),
                    name: name.into(),
                    public_key: "00".repeat(32),
                    old_key: None,
                    key_rotations: 0,
                    platform: "linux".into(),
                    arch: "x86_64".into(),
                    paired_ms: 1,
                    disabled: false,
                    last_seen_ms: 0,
                    going_away: None,
                    descriptor: None,
                    catalog: Default::default(),
                },
            );
            let day = store.day(id, crate::util::now_ms());
            day.calls.insert(
                "fs.read".into(),
                CallStats {
                    count,
                    errors: 0,
                    total_ms: 10,
                    max_ms: 5,
                },
            );
        }
        store.save(d.path()).unwrap();
        let ui = Ui::new(&center(d.path()), None, false);
        let h = ("Host", "127.0.0.1:7480");
        let session = ui.request(req("GET", "/api/session", &[h], "")).await;
        let ck = session_token(&session);
        // The page draws overall numbers, and one machine's from a searchable
        // list of its own: a button and a search field, not a <select>.
        let js = ui
            .request(req("GET", "/app.js", &[h, (SESSION, &ck)], ""))
            .await;
        let js = String::from_utf8(js.body).unwrap();
        for part in ["statsPicker", "role: \"combobox\"", "\"All machines\""] {
            assert!(js.contains(part), "the page has no {part}");
        }
        assert!(!js.contains("createElement(\"select\")") && !js.contains("el(\"select\""));
        // The data: the total, and each paired machine's own numbers by name.
        let r = ui
            .request(req("GET", "/api/stats", &[h, (SESSION, &ck)], ""))
            .await;
        assert_eq!(r.status, 200);
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(v["total"]["calls"]["fs.read"]["count"], 7);
        assert_eq!(v["nodes"]["alpha"]["calls"]["fs.read"]["count"], 3);
        assert_eq!(v["nodes"]["beta"]["calls"]["fs.read"]["count"], 4);
    }

    async fn center_settings(ui: &Ui, body: Option<Value>) -> Result<Value, (u16, Value)> {
        match body {
            Some(b) => ui.api(&req("POST", "/api/center", &[], ""), &b).await,
            None => {
                ui.api(&req("GET", "/api/center", &[], ""), &json!({}))
                    .await
            }
        }
    }

    #[tokio::test]
    async fn the_pairing_code_lifetime_is_a_setting_of_1_to_1440_minutes() {
        let d = tempfile::tempdir().unwrap();
        let c = center(d.path());
        let ui = Ui::new(&c, None, false);
        // Ten minutes unless the owner changes it.
        let got = center_settings(&ui, None).await.unwrap();
        assert_eq!(got["pair_code_minutes"], 10);
        // Within the range it is stored, and the other settings stay.
        center_settings(&ui, Some(json!({"pair_code_minutes": 1440})))
            .await
            .unwrap();
        let got = center_settings(&ui, None).await.unwrap();
        assert_eq!(got["pair_code_minutes"], 1440);
        assert_eq!(got["retention_days"], 30);
        // Outside it, or not a whole number, it is refused with a message and
        // the stored value stays.
        for bad_value in [json!(1441), json!(0), json!(-5), json!(1.5), json!("20")] {
            let (status, body) =
                center_settings(&ui, Some(json!({"pair_code_minutes": bad_value.clone()})))
                    .await
                    .unwrap_err();
            assert_eq!(status, 400, "{bad_value}");
            let msg = body["error"].as_str().unwrap();
            assert!(msg.contains("1 to 1440 minutes"), "{msg}");
            let got = center_settings(&ui, None).await.unwrap();
            assert_eq!(got["pair_code_minutes"], 1440, "{bad_value}");
        }
        // A refused value changes nothing else in the same request.
        let (status, _) = center_settings(
            &ui,
            Some(json!({"name": "other", "pair_code_minutes": 1441})),
        )
        .await
        .unwrap_err();
        assert_eq!(status, 400);
        assert_eq!(center_settings(&ui, None).await.unwrap()["name"], "test");
        // A save without the field leaves it alone, and it survives a restart.
        center_settings(&ui, Some(json!({"retention_days": 5})))
            .await
            .unwrap();
        drop(ui);
        drop(c);
        let ui = Ui::new(&center(d.path()), None, false);
        let got = center_settings(&ui, None).await.unwrap();
        assert_eq!(got["pair_code_minutes"], 1440);
        assert_eq!(got["retention_days"], 5);
    }

    /// The `/* … */` comments of a stylesheet, gone.
    fn without_comments(css: &str) -> String {
        let mut out = String::new();
        let mut rest = css;
        while let Some(at) = rest.find("/*") {
            out.push_str(&rest[..at]);
            rest = rest[at..]
                .find("*/")
                .map_or("", |end| &rest[at + end + 2..]);
        }
        out.push_str(rest);
        out
    }

    /// The declarations of the first rule whose selector line is `head`.
    fn css_block<'a>(css: &'a str, head: &str) -> &'a str {
        let at = css
            .find(&format!("{head} {{"))
            .unwrap_or_else(|| panic!("no `{head}` rule"));
        let body = &css[at..];
        &body[..body.find('}').unwrap()]
    }

    /// `name: value` of each `out property` of a global of theme.slint.
    fn slint_global(theme: &str, global: &str) -> Vec<(String, String)> {
        let at = theme
            .find(&format!("export global {global} {{"))
            .unwrap_or_else(|| panic!("no global {global}"));
        let body = &theme[at..];
        let body = &body[..body.find("\n}").unwrap()];
        body.lines()
            .filter_map(|l| l.trim().strip_prefix("out property <"))
            .filter_map(|l| {
                let (_, rest) = l.split_once("> ")?;
                let (name, value) = rest.split_once(": ")?;
                Some((name.to_string(), value.trim_end_matches(';').to_string()))
            })
            .collect()
    }

    /// The web UI takes the desktop app's design tokens from its
    /// theme.slint: every colour in light and dark, the type scale, the
    /// spaces, the radii, the sizes and the motion, under the same names.
    #[test]
    fn the_web_ui_has_the_desktop_apps_tokens() {
        let theme = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../nerve-node-desktop/ui/theme.slint"
        ))
        .unwrap();
        let css = without_comments(APP_CSS);
        let light = css_block(&css, ":root");
        let dark = css_block(&css, ":root[data-theme=\"dark\"]");
        // Without the theme script the system's scheme picks the dark set.
        let system = css_block(&css, "  :root:not([data-theme])");
        let colours = slint_global(&theme, "Theme");
        let mut seen = 0;
        for (name, value) in &colours {
            // `dark ? #0f1116 : #f4f5f9`; `dark` itself is a bool.
            let Some((d, l)) = value
                .strip_prefix("dark ? ")
                .and_then(|v| v.split_once(" : "))
            else {
                continue;
            };
            seen += 1;
            assert!(light.contains(&format!("--{name}: {l};")), "light --{name}");
            assert!(dark.contains(&format!("--{name}: {d};")), "dark --{name}");
            assert!(
                system.contains(&format!("--{name}: {d};")),
                "system --{name}"
            );
        }
        assert!(seen > 25, "{colours:?}");
        // Lengths and times, each under its prefix; Motion's are those it
        // has when motion is on.
        let lengths = [
            ("Type", "fs-"),
            ("Space", "sp-"),
            ("Radius", "r-"),
            ("Size", ""),
        ];
        for (global, prefix) in lengths.into_iter().chain([("Motion", "")]) {
            for (name, value) in slint_global(&theme, global) {
                let value = value
                    .strip_prefix("on ? ")
                    .map_or(value.as_str(), |v| v.split(" : ").next().unwrap());
                if !(value.ends_with("px") || value.ends_with("ms")) || name.starts_with("icon") {
                    continue;
                }
                let name = if name == "sidebar" {
                    "sidebar-width"
                } else {
                    &name
                };
                assert!(
                    light.contains(&format!("--{prefix}{name}: {value};")),
                    "--{prefix}{name}: {value}"
                );
            }
        }
        assert!(light.contains("--ease: cubic-bezier(0.25, 1, 0.5, 1);"));
        // Less motion when the system asks for it: no time, no rise.
        let reduce = &css[css.find("@media (prefers-reduced-motion: reduce)").unwrap()..];
        let reduce = css_block(reduce, ":root");
        for token in ["--quick", "--base", "--enter", "--leave"] {
            assert!(reduce.contains(&format!("{token}: 0ms;")), "{token}");
        }
        assert!(reduce.contains("--rise: 0px;"));
    }

    /// Help is built as the desktop app's: the keys and the command
    /// reference, each a part that opens and closes, the reference by topic
    /// or from A to Z and filtered.
    #[test]
    fn help_is_built_as_the_desktop_apps() {
        let help = &KIT_JS[KIT_JS.find("function buildHelp").unwrap()..];
        let help = &help[..help.find("\n}\n").unwrap()];
        for part in [
            "expander(\"Keyboard shortcuts\"",
            "expander(\"Command reference\"",
            "[\"By topic\", \"A to Z\"]",
            "\"Filter the commands\"",
            "\"No command matches.\"",
            "el(\"details\", { class: \"cmd\"",
            "el(\"details\", { class: \"ref-group\" }",
        ] {
            assert!(help.contains(part), "Help has no {part}");
        }
        // A part a page leaves out (null) is not drawn as the word.
        let draw = &APP_JS[APP_JS.find("function draw(").unwrap()..];
        let draw = &draw[..draw.find("\n}\n").unwrap()];
        assert_eq!(draw.matches(".filter((p) => p != null)").count(), 2);
        // The same for the local model part, which three places redraw: the
        // filter is in the function, not in each caller.
        let parts = &APP_JS[APP_JS.find("function localInstallParts(").unwrap()..];
        let parts = &parts[..parts.find("\n}\n").unwrap()];
        assert!(parts.contains(".filter((p) => p != null)"), "{parts}");
        assert_eq!(APP_JS.matches("...localInstallParts(").count(), 3);
        assert!(!APP_JS.contains("...localInstallBlocks("));
    }

    /// The owner's note is counted in UTF-8 bytes, as the center counts it
    /// (`maxlength` counts characters, and an umlaut takes two bytes): a
    /// note that is too long is said so and kept in the field, not sent.
    #[test]
    fn the_note_field_counts_bytes_as_the_center_does() {
        assert!(APP_JS.contains(&format!(
            "const NOTE_MAX = {};",
            crate::checker::config::NOTE_MAX
        )));
        let card = &APP_JS[APP_JS.find("function machineCard(").unwrap()..];
        let card = &card[..card.find("\n}\n").unwrap()];
        assert!(
            card.contains("new TextEncoder().encode(noteIn.value.trim()).length"),
            "{card}"
        );
        let save = &card[card.find("const saveNote = ").unwrap()..];
        let save = &save[..save.find("\n  });").unwrap()];
        assert!(
            save.contains("if (n > NOTE_MAX) { notify(") && save.contains("return; }"),
            "{save}"
        );
        assert!(
            save.find("return; }").unwrap() < save.find("await saveChecker()").unwrap(),
            "{save}"
        );
    }

    /// The Capabilities tab's form is checked with the node's own rules
    /// for a capability (nerve_policy::config::form), field by field; a
    /// save that does not pass them is refused before anything is sent, and
    /// a machine the center does not know, or that is offline, is said so.
    #[tokio::test]
    async fn the_capabilities_tab_checks_its_form_before_the_node_does() {
        let d = tempfile::tempdir().unwrap();
        let ui = Ui::new(&center(d.path()), None, false);
        let good = json!({"name": "say.back", "summary": "Says it back.", "effect": "read",
                          "command": "echo {word}",
                          "params": r#"{"type": "object", "properties": {"word": {"type": "string"}}, "required": ["word"]}"#,
                          "result": "", "timeout": "", "platform": "any"});
        let check = async |form: &Value| {
            ui.api(
                &req("POST", "/api/caps/check", &[], ""),
                &json!({"form": form}),
            )
            .await
            .unwrap()
        };
        let v = check(&good).await;
        assert_eq!(v["ok"], true, "{v}");
        for (field, value, said) in [
            ("name", "say", "name it `cap.action`"),
            ("name", "fs.read", "the node's or the center's own"),
            ("command", "echo {nothing}", "{nothing} names no argument"),
            ("command", "\"echo", "a double quote is not closed"),
            ("params", "{", "not JSON"),
            ("params", r#"{"type": "object", "oneOf": []}"#, "oneOf"),
            ("result", "[1]", ""),
            ("timeout", "soon", "seconds, as a whole number"),
            ("timeout", "0", "timeout_secs 0"),
            ("summary", "two\nlines", "one line"),
            ("effect", "Sense", "read, write, execute, sense or actuate"),
            ("platform", "Linux", "any, linux or windows"),
        ] {
            let mut form = good.clone();
            form[field] = json!(value);
            let v = check(&form).await;
            assert_eq!(v["ok"], false, "{field} {value}: {v}");
            let e = v["errors"][field].as_str().unwrap();
            assert!(!e.is_empty() && e.contains(said), "{field} {value}: {v}");
        }
        // A save that does not pass is not sent.
        let mut bad = good.clone();
        bad["command"] = json!("echo {nothing}");
        let (status, e) = ui
            .api(
                &req("POST", "/api/caps/save", &[], ""),
                &json!({"id": "n1", "form": bad, "adding": true}),
            )
            .await
            .unwrap_err();
        assert_eq!(status, 400);
        assert!(
            e["error"].as_str().unwrap().contains("names no argument"),
            "{e}"
        );
        assert!(e["errors"]["command"].is_string(), "{e}");
        // One that passes goes to the node, which is not linked.
        let (status, e) = ui
            .api(
                &req("POST", "/api/caps/save", &[], ""),
                &json!({"id": "n1", "form": good, "adding": true}),
            )
            .await
            .unwrap_err();
        assert_eq!((status, &e["code"]), (409, &json!("unavailable")), "{e}");
        let (status, e) = ui
            .api(
                &req("POST", "/api/caps/remove", &[], ""),
                &json!({"id": "n1", "name": "say.back"}),
            )
            .await
            .unwrap_err();
        assert_eq!((status, &e["code"]), (409, &json!("unavailable")), "{e}");
        // A form with a field the tab does not have is no form.
        let mut odd = good.clone();
        odd["account"] = json!("owner");
        let (status, e) = ui
            .api(
                &req("POST", "/api/caps/check", &[], ""),
                &json!({"form": odd}),
            )
            .await
            .unwrap_err();
        assert_eq!(status, 400, "{e}");
        let mut get = req("GET", "/api/caps", &[], "");
        get.query = "id=nobody".into();
        let (status, _) = ui.api(&get, &json!({})).await.unwrap_err();
        assert_eq!(status, 404);
    }

    /// The Capabilities tab (Q24): a page of its own in the menu, with a
    /// machine picker; drawn only when asked, so the poll does not draw over
    /// its form; units with their source, the left-out ones with the reason;
    /// the form checked by the center as it is typed in, and the node's
    /// refusal shown in it; a machine without the settings grant read only,
    /// with no form.
    /// The audit buttons pin one argument by its field and value: the
    /// checker's allow button saves the rule the node's syntax makes of it,
    /// typed against the machines' schemas; a pin of another shape, one on
    /// a command, or one with a wildcard is refused. The checker page names
    /// the arguments each action takes, and the page's code offers them
    /// under each rule field and on the audit rows (#152, C1).
    #[tokio::test]
    async fn the_audit_buttons_pin_an_argument_and_the_forms_offer_the_fields() {
        use crate::tools::tests::{cap, desc};
        let d = tempfile::tempdir().unwrap();
        let c = center(d.path());
        let lamp = cap(
            "lamp",
            "lamp",
            &[(
                "set",
                nerve_proto::Effect::Actuate,
                json!({"type": "object", "properties": {
                    "room": {"type": "string"}, "level": {"type": "integer"}}}),
            )],
        );
        c.update(|s| {
            let mut n = crate::center::tests::node_record("n1", "linux");
            n.set_descriptor(desc("n1", vec![lamp]));
            s.nodes.insert("n1".into(), n);
        });
        let ui = Ui::new(&c, None, false);
        let allow = async |body: Value| {
            ui.api(&req("POST", "/api/checker/allow", &[], ""), &body)
                .await
        };
        let v = allow(json!({"cap": "lamp", "action": "set", "target": "lamp.set",
                             "pin": {"field": "room", "value": "a,b"}}))
        .await
        .unwrap();
        assert_eq!(v["rule"], "lamp.set:room=a\\,b");
        let v = allow(json!({"cap": "lamp", "action": "set", "target": "lamp.set",
                             "pin": {"field": "level", "value": 3}, "node_id": "n1"}))
        .await
        .unwrap();
        assert_eq!(v["rule"], "lamp.set:level=3");
        let rules: Vec<String> = c.read(|s| {
            s.checker
                .allow_rules
                .iter()
                .map(|a| a.rule.clone())
                .collect()
        });
        assert!(
            rules.contains(&"lamp.set:room=a\\,b".to_string()),
            "{rules:?}"
        );
        for (body, said) in [
            (
                json!({"cap": "lamp", "action": "set", "target": "lamp.set", "pin": {"field": "size", "value": 1}}),
                "no argument size",
            ),
            (
                json!({"cap": "lamp", "action": "set", "target": "lamp.set", "pin": {"field": "level", "value": "x"}}),
                "is an integer",
            ),
            (
                json!({"cap": "lamp", "action": "set", "target": "lamp.set", "pin": {"value": 1}}),
                "a pin is {field, value}",
            ),
            (
                json!({"cap": "lamp", "action": "set", "target": "lamp.set", "wildcard": true, "pin": {"field": "room", "value": "x"}}),
                "no wildcard form",
            ),
            (
                json!({"cap": "exec", "action": "run", "target": "ls", "pin": {"field": "command", "value": "ls"}}),
                "names its command",
            ),
        ] {
            let (status, e) = allow(body.clone()).await.unwrap_err();
            assert_eq!(status, 400, "{body}");
            assert!(e["error"].as_str().unwrap().contains(said), "{body}: {e}");
        }
        let (status, e) = ui
            .api(
                &req("POST", "/api/audit/rule", &[], ""),
                &json!({"list": "sudo", "cap": "lamp", "action": "set", "target": "lamp.set",
                        "node_id": "n1", "pin": {"field": "room", "value": "x"}}),
            )
            .await
            .unwrap_err();
        assert_eq!(status, 400);
        assert!(e["error"].as_str().unwrap().contains("sudo list"), "{e}");
        let v = ui
            .api(&req("GET", "/api/checker", &[], ""), &json!({}))
            .await
            .unwrap();
        assert_eq!(
            v["fields"]["lamp.set"],
            json!(["level (an integer)", "room (a string)"])
        );
        assert_eq!(v["stale"], json!({}));
        // The page offers them: under each rule field, and on the rows.
        let row = &APP_JS[APP_JS.find("function auditRow(").unwrap()..];
        let row = &row[..row.find("\n}\n").unwrap()];
        for part in [
            "const pins = pinPicker(d, auditKey);",
            "pin: pin ? pin() : null",
            r#"ruleBtn("Allow with this value", "", "allow", false, null, pins.pin)"#,
            r#"ruleBtn("Deny with this value", "danger-soft", "deny", false, null, pins.pin)"#,
        ] {
            assert!(row.contains(part), "{part}");
        }
        let checker = &APP_JS[APP_JS.find("function checkerAuditRow(").unwrap()..];
        assert!(checker.contains(r#"btn("Allow with this value", "", allow(false, pins.pin)"#));
        assert_eq!(
            APP_JS.matches(", ruleIn, ruleFieldsHint(ruleIn))").count(),
            3
        );
        assert!(APP_JS.contains("    staleBanner(c.meta.stale),\n"));
        assert!(APP_JS.contains("((state.checker && state.checker.meta.fields) || {})[scope]"));
    }

    #[test]
    fn the_capabilities_tab_has_a_picker_a_checked_form_and_a_read_only_view() {
        assert!(INDEX.contains(r##"<a href="#capabilities" data-page="capabilities">"##));
        assert!(APP_JS.contains(r#"capabilities: { title: "Capabilities", view: pageCaps },"#));
        let draw = &APP_JS[APP_JS.find("function draw(").unwrap()..];
        assert!(draw.contains(
            r#"if (page === "settings" || page === "checker" || page === "capabilities") {"#
        ));
        let page = &APP_JS[APP_JS.find("function pageCaps(").unwrap()..];
        let page = &page[..page.find("\n}\n").unwrap()];
        for part in [
            "capsPicker.root",
            "d.units.map(capUnitRow)",
            "d.broken.map(",
            "b.reason",
            "!d.settings_write ? banner(",
            "d.settings_write ? addedSection(d) : null",
            // A machine that did not load says why, beside the picker.
            "c.failed ? banner(\"error\", \"alert\", `The machine's capabilities did not load: ${c.failed}`) : loading()",
        ] {
            assert!(page.contains(part), "{part}: {page}");
        }
        let load = &APP_JS[APP_JS.find("async function loadCaps(").unwrap()..];
        let load = &load[..load.find("\n}\n").unwrap()];
        for part in [
            "`/api/caps?id=${encodeURIComponent(state.capsNode)}`",
            // One removed meanwhile: the machines are read again.
            // A load a later pick took over ends quietly.
            "      if (e.auth) throw e;\n",
            "      if (run !== capsRun) return;\n      // A machine removed",
            "if (e.status === 404 && !fresh) {",
            "return loadCaps(true);",
            "state.caps = { nodes, data: null, failed: e.message, form: null };",
        ] {
            assert!(load.contains(part), "{part}: {load}");
        }
        // Picking one keeps the picker on the page and says what failed.
        let pick = &APP_JS[APP_JS.find("const capsPicker = picker(").unwrap()..];
        let pick = &pick[..pick.find("\n});\n").unwrap()];
        for part in [
            "state.caps = { nodes: state.caps.nodes, data: null, form: null };",
            "loadCaps().catch((e) => { if (!e.auth) notify(e.message, \"error\"); });",
        ] {
            assert!(pick.contains(part), "{part}: {pick}");
        }
        assert!(KIT_JS.contains("err.status = r.status;"));
        let row = &APP_JS[APP_JS.find("function capUnitRow(").unwrap()..];
        let row = &row[..row.find("\n}\n").unwrap()];
        assert!(row.contains("u.source") && row.contains("effectPill(u.effect)"));
        let added = &APP_JS[APP_JS.find("function addedSection(").unwrap()..];
        let added = &added[..added.find("\n}\n").unwrap()];
        assert!(
            added.contains("a.refused ? null : btn(\"Add a capability\""),
            "{added}"
        );
        assert!(added.contains("takes no capability from a center: ${a.refused}"));
        let entry = &APP_JS[APP_JS.find("function addedRow(").unwrap()..];
        let entry = &entry[..entry.find("\n}\n").unwrap()];
        assert!(entry.contains("\"/api/caps/remove\"") && entry.contains("await modal("));
        assert!(entry.contains("e.left_out"));
        // One the machine neither offers nor leaves out says why.
        assert!(entry.contains("const idle = notOffered(d, e);") && entry.contains("    idle);"));
        let idle = &APP_JS[APP_JS.find("function notOffered(").unwrap()..];
        let idle = &idle[..idle.find("\n}\n").unwrap()];
        for part in [
            "if (e.left_out || d.units.some((u) => u.name === e.name)) return null;",
            "only the machine's owner turns it on",
            "in folder mode with an on for it (\"caps\": {\"${e.name}\": \"on\"})",
            "in allowlist mode with the allow rule ${e.name}.",
        ] {
            assert!(idle.contains(part), "{part}: {idle}");
        }
        let form = &APP_JS[APP_JS.find("function capForm(").unwrap()..];
        let form = &form[..form.find("\n}\n").unwrap()];
        for part in [
            "api(\"POST\", \"/api/caps/check\", { form: v })",
            "api(\"POST\", \"/api/caps/save\", { id: d.node.id, form: v, adding: f.adding })",
            "if (e.body && e.body.errors) { show(e.body.errors); return; }",
            "The machine refused: ${e.message}",
            "readonly: !f.adding",
        ] {
            assert!(form.contains(part), "{part}");
        }
        // Every field the center checks has its place for what is wrong.
        for f in ["name", "timeout", "summary", "command", "params", "result"] {
            assert!(form.contains(&format!("field(\"{f}\", ")), "{f}");
        }
        for f in ["effect", "platform"] {
            assert!(
                form.contains(&format!("errs.{f} = el(\"span\""))
                    && form.contains(&format!(", errs.{f})")),
                "{f}"
            );
        }
        assert!(KIT_JS.contains("err.body = v;"));
        assert!(!APP_JS.contains("el(\"select\""));
    }

    /// The node card names each action the center left out with its
    /// reason, from the overview's `broken`.
    #[test]
    fn the_node_card_shows_what_the_center_left_out() {
        let card = &APP_JS[APP_JS.find("function nodeCard(").unwrap()..];
        let card = &card[..card.find("\n}\n").unwrap()];
        assert!(card.contains("const broken = n.broken || [];"), "{card}");
        assert!(card.contains("broken.length"), "{card}");
        // A neutral heading: a unit may be left out for its name as well
        // as for a schema the center cannot check.
        assert!(card.contains("\"Not offered to the agent:\""), "{card}");
        assert!(
            card.contains("broken.map((b) =>")
                && card.contains("b.name")
                && card.contains("b.reason"),
            "{card}"
        );
    }

    /// A button's handler gets the event: the switches of the Action checker
    /// read `ev.currentTarget.checked`, and without the event they threw
    /// before they saved anything.
    #[test]
    fn a_button_action_gets_the_event() {
        let act = &KIT_JS[KIT_JS.find("function act(").unwrap()..];
        let act = &act[..act.find("\n}\n").unwrap()];
        assert!(act.contains("await fn(ev)"), "{act}");
        assert!(!act.contains("await fn()"), "{act}");
        // Every handler that reads the event is one of the switches, which
        // are wrapped in act.
        let uses: Vec<_> = APP_JS
            .lines()
            .filter(|l| l.contains("act(async (ev) =>"))
            .collect();
        assert_eq!(uses.len(), 2, "{uses:?}");
        assert!(uses.iter().all(|l| l.contains("ev.currentTarget.checked")));
    }

    /// The Action checker page changes its working copy and then saves it.
    /// A refused save must not leave the change behind, or the next save
    /// (of anything on the page) sends it: the copy goes back to what the
    /// center kept, and the error still reaches the toast. The model form
    /// changes a copy and not the working copy. (The browser check is
    /// `checker-failed-save.js` in the review tools.)
    #[test]
    fn a_refused_checker_save_leaves_no_change_behind() {
        let save = &APP_JS[APP_JS.find("async function saveChecker(").unwrap()..];
        let save = &save[..save.find("\n}\n").unwrap()];
        let catch = &save[save.find("catch (e)").unwrap()..];
        assert!(catch.contains("c.cfg = structuredClone(c.saved)"), "{save}");
        assert!(catch.contains("draw(true)"), "{save}");
        assert!(catch.contains("throw e"), "{save}");
        let load = &APP_JS[APP_JS.find("async function loadChecker(").unwrap()..];
        let load = &load[..load.find("\n}\n").unwrap()];
        assert!(load.contains("saved: structuredClone(cfg)"), "{load}");
        let model = &APP_JS[APP_JS.find("function modelCard(").unwrap()..];
        let model = &model[..model.find("\n}\n").unwrap()];
        assert!(model.contains("await saveChecker(next)"), "{model}");
        assert!(!model.contains("m.source ="), "{model}");
        // The page saves in one place only.
        assert_eq!(
            APP_JS
                .matches("await api(\"POST\", \"/api/checker\",")
                .count(),
            1
        );
    }

    /// A save draws the page anew, and the focus is put back on the control
    /// it was on: a keyboard user toggling switches goes on from there, and
    /// does not start at the top of the page again.
    #[test]
    fn a_page_drawn_anew_keeps_the_focus() {
        let replace = &KIT_JS[KIT_JS.find("function replacePage(").unwrap()..];
        let replace = &replace[..replace.find("\n}\n").unwrap()];
        assert!(replace.contains("restoreFocus(spot)"), "{replace}");
        assert!(replace.contains("focusSpot(active)"), "{replace}");
        let act = &KIT_JS[KIT_JS.find("function act(").unwrap()..];
        let act = &act[..act.find("\n}\n").unwrap()];
        // Taken before the control is made busy: a disabled control may
        // already have lost the focus.
        assert!(
            act.find("pendingFocus = spot").unwrap() < act.find("setBusy(b, true)").unwrap(),
            "{act}"
        );
        // The pages that are redrawn on a save go through replacePage.
        assert_eq!(APP_JS.matches("replacePage(").count(), 2);
        assert_eq!(KIT_JS.matches("replacePage(").count(), 1);
    }

    /// The focus goes back to the control by what it is, never by where it
    /// sat (review round 3, finding 1): after a list gained or lost an item,
    /// a position names the End, Remove or Disable of another item, and
    /// Enter acts on an item the user never picked. A control without a
    /// `data-focus` key, a key that is gone and a key that is not unique
    /// all send the focus to the section's heading, which does nothing on
    /// Enter. (The browser check is `focus-identity.js` in the review tools.)
    #[test]
    fn the_focus_is_restored_by_identity_not_by_position() {
        let spot = &KIT_JS[KIT_JS.find("function focusSpot(").unwrap()..];
        let spot = &spot[..spot.find("\n}\n").unwrap()];
        assert!(!spot.contains("indexOf"), "{spot}");
        assert!(!spot.contains("path"), "{spot}");
        assert!(spot.contains("node.dataset.focus"), "{spot}");
        let target = &KIT_JS[KIT_JS.find("function focusTarget(").unwrap()..];
        let target = &target[..target.find("\n}\n").unwrap()];
        assert!(target.contains("found.length === 1"), "{target}");
        let restore = &KIT_JS[KIT_JS.find("function restoreFocus(").unwrap()..];
        let restore = &restore[..restore.find("\n}\n").unwrap()];
        assert!(!restore.contains(".children["), "{restore}");
        // No early return for a spot without a key: it reaches the
        // heading like a key that is gone (review round 5, finding 1).
        assert!(!restore.contains("if (!spot.key)"), "{restore}");
        assert!(
            restore.contains("spot.key && focusTarget(spot.key)"),
            "{restore}"
        );
        assert!(restore.contains("querySelector(\"h3\")"), "{restore}");
        // The heading takes the focus but is not a stop for Tab.
        assert!(KIT_JS.contains("el(\"h3\", { tabindex: \"-1\""));
        // Every control that acts on one item, without asking, has a key
        // that names the item.
        for (label, kind) in [
            ("btn(\"End\"", ":end`"),
            ("btn(n.disabled ?", ":disable`"),
            (
                "btn(\"Remove\", \"danger-soft\", act(async () => { cfg.",
                ":remove`",
            ),
            ("btn(\"Switch on again\"", ":on`"),
            ("btn(\"Delete\"", ":delete`"),
        ] {
            let lines: Vec<_> = APP_JS.lines().filter(|l| l.contains(label)).collect();
            assert!(!lines.is_empty(), "{label}");
            assert!(
                lines.iter().all(|l| l.contains(kind) && l.contains("${")),
                "{label}: {lines:?}"
            );
        }
        // A blocklist or allow entry is named by what it is (a built-in by
        // its id, an own entry by rule, scope and note), and by the list it
        // is shown in (a machine's card repeats the entries).
        assert!(APP_JS.contains("`block:${where}:${e.id ? `id=${e.id}` :"));
        assert!(APP_JS.contains("`allow:${where}:${a.rule}|${a.node_id || \"\"}:remove`"));
        assert!(APP_JS.contains("`off:${m.id}:${e.id ? `id=${e.id}` :"));
        // A key the page holds twice (an own entry with a built-in's rule
        // and note, a rule added twice) names no control: focusSpot drops
        // it, so removing one of two does not hand the focus, and Enter, to
        // the other.
        assert!(spot.contains("focusTarget(node.dataset.focus)"), "{spot}");
        // The built-in ids the keys rest on are there and differ.
        let ids: Vec<_> = crate::checker::config::default_blocklist()
            .into_iter()
            .map(|e| e.id)
            .collect();
        assert!(ids.iter().all(|i| !i.is_empty()));
        let mut unique = ids.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), ids.len());
        // A session's End is named by the session.
        assert!(APP_JS.contains("session:${s.id}:end"));
    }

    /// A text field that gets the focus back gets what was typed into it back
    /// as well (review round 5, finding 2): the redraw builds the field from
    /// the saved state, and the user would type on into an empty one. The
    /// text is read from the old page when the focus is taken, only for a
    /// field, and put back only into a field of the same kind. (The browser
    /// check is part 5 of `focus-identity.js` in the review tools.)
    #[test]
    fn a_text_field_gets_back_what_was_typed_with_the_focus() {
        let spot = &KIT_JS[KIT_JS.find("function focusSpot(").unwrap()..];
        let spot = &spot[..spot.find("\n}\n").unwrap()];
        assert!(spot.contains("isTextField(node)"), "{spot}");
        assert!(spot.contains("node.value"), "{spot}");
        assert!(spot.contains("node.selectionStart"), "{spot}");
        let restore = &KIT_JS[KIT_JS.find("function restoreFocus(").unwrap()..];
        let restore = &restore[..restore.find("\n}\n").unwrap()];
        assert!(restore.contains("same.value = t.value"), "{restore}");
        assert!(restore.contains("same.setSelectionRange("), "{restore}");
        assert!(
            restore.contains("same.type === spot.node.type"),
            "{restore}"
        );
        // Buttons and switches are not text fields.
        let kinds = &KIT_JS[KIT_JS.find("function isTextField(").unwrap()..];
        let kinds = &kinds[..kinds.find("\n}\n").unwrap()];
        assert!(kinds.contains("\"checkbox\""), "{kinds}");
    }

    /// The checker's text fields and the Audit page's buttons have a key too,
    /// so a page drawn anew (the end of a save, the minute turning) keeps the
    /// focus there and not on `<body>`. (The browser check is part 5 of
    /// `focus-identity.js` in the review tools.)
    #[test]
    fn the_checkers_text_fields_and_audit_buttons_keep_the_focus() {
        for field in [
            "\"data-focus\": \"blocklist:rule\"",
            "\"data-focus\": \"blocklist:note\"",
            "\"data-focus\": \"allow:rule\"",
            "\"data-focus\": `node:${m.id}:rule`",
            "\"data-focus\": \"model:endpoint_url\"",
            "\"data-focus\": \"model:endpoint_model\"",
            "\"data-focus\": \"model:token\"",
            "\"data-focus\": \"model:threshold\"",
            "\"data-focus\": \"model:timeout\"",
            "\"data-focus\": \"model:instructions\"",
            "\"data-focus\": \"model:criteria_true\"",
            "\"data-focus\": \"model:criteria_false\"",
        ] {
            assert!(APP_JS.contains(field), "{field}");
        }
        // A decision has no id: its time, machine and call name the buttons.
        let audit = "`audit:${d.ts}:${d.node_id}:${d.cap}.${d.action}`";
        assert_eq!(APP_JS.matches(audit).count(), 2);
        assert!(
            APP_JS.contains(
                "btn(label, kind, rule(list, wildcard, pin), ic, `${auditKey}:${label}`)"
            )
        );
        // The pin of an argument, and its buttons, are named by the entry.
        assert!(APP_JS.contains("key: `${auditKey}:pin`"));
        assert!(APP_JS.contains("`${auditKey}:Allow with this value`"));
        assert!(APP_JS.contains("`${auditKey}:Allow as wildcard`"));
    }

    /// A save in flight pulls the focus back only while the focus is still
    /// on the control that started it (or has fallen to the page because
    /// that control was replaced), and only on the page it started on
    /// (review round 3, finding 2).
    #[test]
    fn a_save_in_flight_does_not_pull_the_focus_back() {
        let replace = &KIT_JS[KIT_JS.find("function replacePage(").unwrap()..];
        let replace = &replace[..replace.find("\n}\n").unwrap()];
        assert!(replace.contains("p.page === current()"), "{replace}");
        assert!(replace.contains("active === p.node"), "{replace}");
        assert!(replace.contains("document.body"), "{replace}");
        let go = &APP_JS[APP_JS.find("function go(").unwrap()..];
        let go = &go[..go.find("\n}\n").unwrap()];
        assert!(go.contains("pendingFocus = null"), "{go}");
        // A save no button started (a picker's) holds the focus the same way,
        // and the holder lets go only of its own spot.
        let quietly = &APP_JS[APP_JS.find("function quietly(").unwrap()..];
        let quietly = &quietly[..quietly.find("\n}\n").unwrap()];
        assert!(quietly.contains("pendingFocus = spot"), "{quietly}");
        assert!(quietly.contains("if (pendingFocus === spot)"), "{quietly}");
    }

    /// The Action checker page saves one change at a time: each save posts
    /// the whole working copy, so a second change made while the first runs
    /// rides along, and would be saved although the first was refused and
    /// taken back (review round 3, finding 3). The page's controls are off
    /// from the start of a save until it has settled, and are on again
    /// before the page is drawn anew (a disabled control cannot take the
    /// focus). (The browser check is `focus-identity.js` in the review tools.)
    #[test]
    fn the_checker_page_saves_one_change_at_a_time() {
        let save = &APP_JS[APP_JS.find("async function saveChecker(").unwrap()..];
        let save = &save[..save.find("\n}\n").unwrap()];
        assert!(
            save.find("lockSaves(true)").unwrap() < save.find("await api(").unwrap(),
            "{save}"
        );
        let catch = &save[save.find("catch (e)").unwrap()..];
        assert!(
            catch.find("endSave()").unwrap() < catch.find("draw(true)").unwrap(),
            "{save}"
        );
        assert!(save.contains("await loadChecker(true)"), "{save}");
        let fin = &save[save.find("finally").unwrap()..];
        assert!(fin.contains("endSave()"), "{save}");
        let load = &APP_JS[APP_JS.find("async function loadChecker(").unwrap()..];
        let load = &load[..load.find("\n}\n").unwrap()];
        assert!(
            load.find("endSave()").unwrap() < load.find("draw(true)").unwrap(),
            "{load}"
        );
        // A page drawn while a save runs is locked too.
        let draw = &APP_JS[APP_JS.find("function draw(").unwrap()..];
        let draw = &draw[..draw.find("\n}\n").unwrap()];
        assert!(draw.contains("checkerSaving) lockSaves(true)"), "{draw}");
        // Nothing else on the page posts the whole copy.
        assert_eq!(
            APP_JS
                .matches("await api(\"POST\", \"/api/checker\",")
                .count(),
            1
        );
    }

    /// The relative luminance of `#rrggbb`, as WCAG defines it.
    fn luminance(hex: &str) -> f64 {
        let c = |i: usize| {
            let v = f64::from(u8::from_str_radix(&hex[1 + 2 * i..3 + 2 * i], 16).unwrap()) / 255.0;
            if v <= 0.03928 {
                v / 12.92
            } else {
                ((v + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * c(0) + 0.7152 * c(1) + 0.0722 * c(2)
    }

    fn contrast(a: &str, b: &str) -> f64 {
        let (a, b) = (luminance(a), luminance(b));
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    }

    /// The off track of a switch shows the state, so it needs 3:1 against
    /// what it sits on (WCAG 1.4.11), in both themes, and the web UI and the
    /// app take it from the same token.
    #[test]
    fn the_off_switch_has_the_contrast_of_a_control() {
        let theme = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../nerve-node-desktop/ui/theme.slint"
        ))
        .unwrap();
        let colours = slint_global(&theme, "Theme");
        let pair = |name: &str| {
            let (_, v) = colours.iter().find(|(n, _)| n == name).unwrap();
            let (d, l) = v
                .strip_prefix("dark ? ")
                .unwrap()
                .split_once(" : ")
                .unwrap();
            (d.to_string(), l.to_string())
        };
        let (off_dark, off_light) = pair("switch-off");
        for surface in ["window", "surface", "surface-alt"] {
            let (d, l) = pair(surface);
            assert!(contrast(&off_dark, &d) >= 3.0, "dark {surface}");
            assert!(contrast(&off_light, &l) >= 3.0, "light {surface}");
        }
        // The white knob has to show on the track as well.
        assert!(contrast(&off_dark, "#ffffff") >= 3.0);
        assert!(contrast(&off_light, "#ffffff") >= 3.0);
        let widgets = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../nerve-node-desktop/ui/widgets.slint"
        ))
        .unwrap();
        assert!(widgets.contains("root.checked ? Theme.accent : Theme.switch-off;"));
        let css = without_comments(APP_CSS);
        assert!(css_block(&css, ".switch input").contains("background: var(--switch-off);"));
    }

    #[tokio::test]
    async fn open_ui_needs_a_loopback_host_and_its_session() {
        let d = tempfile::tempdir().unwrap();
        let ui = Ui::new(&center(d.path()), None, false);
        let h = ("Host", "127.0.0.1:7480");
        // A rebound name is refused.
        let r = ui
            .request(req("GET", "/api/session", &[("Host", "evil.example")], ""))
            .await;
        assert_eq!(r.status, 403);
        let r = ui.request(req("GET", "/api/session", &[h], "")).await;
        assert_eq!(r.status, 200);
        let ck = session_token(&r);
        // No session, no API; a cookie with the session is no session.
        assert_eq!(
            ui.request(req("GET", "/api/overview", &[h], ""))
                .await
                .status,
            401
        );
        let cookie = format!("nerve_ui={ck}");
        assert_eq!(
            ui.request(req("GET", "/api/overview", &[h, ("Cookie", &cookie)], ""))
                .await
                .status,
            401
        );
        assert_eq!(
            ui.request(req("GET", "/api/overview", &[h, (SESSION, &ck)], ""))
                .await
                .status,
            200
        );
        // A change from another origin is refused.
        let r = ui
            .request(req(
                "POST",
                "/api/pair",
                &[h, (SESSION, &ck), ("Origin", "http://evil.example")],
                "",
            ))
            .await;
        assert_eq!(r.status, 403);
        let r = ui
            .request(req("POST", "/api/pair", &[h, (SESSION, &ck)], ""))
            .await;
        assert_eq!(r.status, 200);
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        assert!(v["link"].as_str().unwrap().starts_with("nerve://pair?"));
    }

    const TOKEN: &str = "nrv_test-token-long";
    const HOST: (&str, &str) = ("Host", "center.example:7480");

    fn locked(dir: &std::path::Path) -> Arc<Ui> {
        Ui::new(&center(dir), Some(TOKEN.into()), true)
    }

    fn header<'a>(r: &'a Response, name: &str) -> Option<&'a str> {
        r.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn body(r: &Response) -> String {
        String::from_utf8_lossy(&r.body).into_owned()
    }

    fn json(r: &Response) -> Value {
        serde_json::from_slice(&r.body).unwrap()
    }

    /// Posts the token as the login page does, and returns the answer.
    async fn sign_in(ui: &Ui, token: &str) -> Response {
        ui.request(req(
            "POST",
            "/login",
            &[HOST, ("Content-Type", "application/json")],
            &json!({ "token": token }).to_string(),
        ))
        .await
    }

    /// The API routes a session is needed for, with a request of each.
    const API: [(&str, &str); 6] = [
        ("GET", "/api/overview"),
        ("GET", "/api/stats"),
        ("GET", "/api/audit"),
        ("GET", "/api/tokens"),
        ("GET", "/api/log/download"),
        ("POST", "/api/pair"),
    ];

    #[tokio::test]
    async fn without_a_session_every_api_call_is_refused_and_the_page_is_public() {
        let d = tempfile::tempdir().unwrap();
        let ui = locked(d.path());
        for (method, path) in API {
            let r = ui.request(req(method, path, &[HOST], "")).await;
            assert_eq!(r.status, 401, "{path}");
        }
        // The page and what it loads hold nothing secret: a navigation
        // carries no session, and the page asks /api/session first.
        for (path, kind) in [
            ("/", "text/html"),
            ("/index.html", "text/html"),
            ("/app.js", "text/javascript"),
            ("/kit.js", "text/javascript"),
            ("/app.css", "text/css"),
            ("/login.js", "text/javascript"),
            ("/theme-init.js", "text/javascript"),
            ("/icon.svg", "image/svg+xml"),
        ] {
            let r = ui.request(req("GET", path, &[HOST], "")).await;
            assert_eq!(r.status, 200, "{path}");
            assert!(header(&r, "Content-Type").unwrap().starts_with(kind));
        }
        assert_eq!(
            ui.request(req("GET", "/missing", &[HOST], "")).await.status,
            404
        );
        let r = ui.request(req("GET", "/api/session", &[HOST], "")).await;
        let v = json(&r);
        assert_eq!(
            (v["login"].clone(), v["logged_in"].clone()),
            (true.into(), false.into())
        );
        assert!(v.get("session").is_none(), "no session without a login");
        let r = ui.request(req("GET", "/login", &[HOST], "")).await;
        assert_eq!(r.status, 200);
        assert!(body(&r).contains("Harness token"));
        assert!(body(&r).contains(r#"src="/login.js""#));
    }

    #[tokio::test]
    async fn wrong_token_is_refused_without_echoing_it() {
        let d = tempfile::tempdir().unwrap();
        let ui = locked(d.path());
        let r = sign_in(&ui, "not-the-secret").await;
        assert_eq!(r.status, 401);
        assert!(json(&r).get("session").is_none());
        assert_eq!(json(&r)["error"], WRONG_TOKEN);
        assert!(!body(&r).contains("not-the-secret"));
        // An empty post is no better.
        assert_eq!(sign_in(&ui, "").await.status, 401);
        let r = ui.request(req("POST", "/login", &[HOST], "")).await;
        assert_eq!(r.status, 401);
        // The token is not accepted in a URL.
        let mut q = req("POST", "/login", &[HOST], "");
        q.query = format!("token={TOKEN}");
        assert_eq!(ui.request(q).await.status, 401);
    }

    #[tokio::test]
    async fn correct_token_hands_out_a_session_for_the_header() {
        let d = tempfile::tempdir().unwrap();
        let ui = locked(d.path());
        let r = sign_in(&ui, TOKEN).await;
        assert_eq!(r.status, 200);
        assert!(header(&r, "Set-Cookie").is_none(), "no cookie");
        assert!(!body(&r).contains(TOKEN));
        let ck = session_token(&r);
        let with = [HOST, (SESSION, ck.as_str())];
        for (method, path) in API {
            let r = ui.request(req(method, path, &with, "")).await;
            assert_ne!(r.status, 401, "{path}");
        }
        let r = ui.request(req("GET", "/api/session", &with, "")).await;
        let v = json(&r);
        assert_eq!(v["logged_in"], true);
        // The session lasts 12 hours.
        ui.sessions.age(&ck, webui::SESSION_TTL);
        assert_eq!(
            ui.request(req("GET", "/api/overview", &with, ""))
                .await
                .status,
            401
        );
    }

    #[tokio::test]
    async fn the_token_is_read_from_the_form_encoding_too() {
        let d = tempfile::tempdir().unwrap();
        let ui = Ui::new(&center(d.path()), Some("p&w=d x%".into()), true);
        let form = |t: &str| {
            req(
                "POST",
                "/login",
                &[HOST, ("Content-Type", "application/x-www-form-urlencoded")],
                &format!("token={t}"),
            )
        };
        let r = ui.request(form("p%26w%3Dd+x%25")).await;
        assert_eq!(r.status, 200);
        session_token(&r);
        // The raw text is not the token.
        assert_eq!(ui.request(form("p&w=d x%")).await.status, 401);
        assert_eq!(sign_in(&ui, "p&w=d x%").await.status, 200);
    }

    #[tokio::test]
    async fn logout_ends_the_session() {
        let d = tempfile::tempdir().unwrap();
        let ui = locked(d.path());
        let ck = session_token(&sign_in(&ui, TOKEN).await);
        let with = [HOST, (SESSION, ck.as_str())];
        let r = ui.request(req("POST", "/logout", &with, "")).await;
        assert_eq!(r.status, 200);
        // The old session is dead on the server too, not just in the tab.
        assert_eq!(
            ui.request(req("GET", "/api/overview", &with, ""))
                .await
                .status,
            401
        );
        // Logging out twice, or without a session, is harmless.
        let r = ui.request(req("POST", "/logout", &[HOST], "")).await;
        assert_eq!(r.status, 200);
        // Only a post logs out: a link someone else planted does not.
        let ck = session_token(&sign_in(&ui, TOKEN).await);
        let with = [HOST, (SESSION, ck.as_str())];
        assert_eq!(
            ui.request(req("GET", "/logout", &with, "")).await.status,
            404
        );
        assert_eq!(
            ui.request(req("GET", "/api/overview", &with, ""))
                .await
                .status,
            200
        );
    }

    #[tokio::test]
    async fn login_and_logout_refuse_other_origins() {
        let d = tempfile::tempdir().unwrap();
        let ui = locked(d.path());
        let own = format!("https://{}", HOST.1);
        let body = json!({ "token": TOKEN }).to_string();
        for origin in ["https://evil.example", "null", "http://center.example:1"] {
            let r = ui
                .request(req(
                    "POST",
                    "/login",
                    &[
                        HOST,
                        ("Origin", origin),
                        ("Content-Type", "application/json"),
                    ],
                    &body,
                ))
                .await;
            assert_eq!(r.status, 403, "{origin}");
            assert!(json_or_null(&r).get("session").is_none());
        }
        // The browser's own post names this host.
        let r = ui
            .request(req(
                "POST",
                "/login",
                &[HOST, ("Origin", &own), ("Content-Type", "application/json")],
                &body,
            ))
            .await;
        assert_eq!(r.status, 200);
        let ck = session_token(&r);
        let r = ui
            .request(req(
                "POST",
                "/logout",
                &[HOST, (SESSION, &ck), ("Origin", "https://evil.example")],
                "",
            ))
            .await;
        assert_eq!(r.status, 403);
        let r = ui
            .request(req("GET", "/api/overview", &[HOST, (SESSION, &ck)], ""))
            .await;
        assert_eq!(r.status, 200);
    }

    /// An answer's JSON, or null for a plain-text one.
    fn json_or_null(r: &Response) -> Value {
        serde_json::from_slice(&r.body).unwrap_or(Value::Null)
    }

    #[tokio::test]
    async fn repeated_wrong_tokens_are_throttled() {
        let d = tempfile::tempdir().unwrap();
        let ui = locked(d.path());
        for _ in 0..LOGIN_TRIES {
            assert_eq!(sign_in(&ui, "nope").await.status, 401);
        }
        // Even the right token waits until the minute is over.
        let r = sign_in(&ui, TOKEN).await;
        assert_eq!(r.status, 429);
        assert_eq!(header(&r, "Retry-After"), Some("60"));
        assert_eq!(json(&r)["error"], TOO_MANY);
        assert!(json(&r).get("session").is_none());
    }

    #[tokio::test]
    async fn an_open_ui_has_no_login() {
        let d = tempfile::tempdir().unwrap();
        let ui = Ui::new(&center(d.path()), None, false);
        let h = ("Host", "127.0.0.1:7480");
        let r = ui.request(req("GET", "/", &[h], "")).await;
        assert_eq!(r.status, 200);
        let r = ui.request(req("GET", "/login", &[h], "")).await;
        assert_eq!((r.status, header(&r, "Location")), (303, Some("/")));
        let r = ui.request(req("POST", "/login", &[h], "token=x")).await;
        assert_eq!((r.status, header(&r, "Location")), (303, Some("/")));
        let r = ui.request(req("POST", "/logout", &[h], "")).await;
        assert_eq!(r.status, 200);
        // Each tab that asks gets a session of its own.
        let a = session_token(&ui.request(req("GET", "/api/session", &[h], "")).await);
        let b = session_token(&ui.request(req("GET", "/api/session", &[h], "")).await);
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn a_token_made_in_the_ui_logs_in_and_a_session_ends_with_its_deletion() {
        let d = tempfile::tempdir().unwrap();
        let c = center(d.path());
        // The token is made in the open UI, as on a fresh center.
        let open = Ui::new(&c, None, false);
        let h = ("Host", "127.0.0.1:7480");
        let r = open.request(req("GET", "/api/session", &[h], "")).await;
        let ck = session_token(&r);
        let made = |label: &str| {
            req(
                "POST",
                "/api/tokens/create",
                &[h, (SESSION, &ck)],
                &format!(r#"{{"label":"{label}"}}"#),
            )
        };
        let first = serde_json::from_slice::<Value>(&open.request(made("a")).await.body).unwrap();
        let (token, id) = (
            first["token"].as_str().unwrap().to_string(),
            first["id"].as_str().unwrap().to_string(),
        );
        let other = serde_json::from_slice::<Value>(&open.request(made("b")).await.body).unwrap();

        // Later, with the login on, that same token is the login.
        let ui = Ui::new(&c, None, true);
        assert_eq!(sign_in(&ui, "nrv_not-made-here").await.status, 401);
        let r = sign_in(&ui, &format!("  {token}\r\n")).await;
        assert_eq!(r.status, 200);
        let session = session_token(&r);
        let with = [HOST, (SESSION, session.as_str())];
        assert_eq!(
            ui.request(req("GET", "/api/overview", &with, ""))
                .await
                .status,
            200
        );

        // The other token's session survives deleting this one; this one's does not.
        let ck2 = session_token(&sign_in(&ui, other["token"].as_str().unwrap()).await);
        let del = req(
            "POST",
            "/api/tokens/delete",
            &[HOST, (SESSION, &session)],
            &format!(r#"{{"id":"{id}"}}"#),
        );
        assert_eq!(ui.request(del).await.status, 200);
        let r = ui.request(req("GET", "/api/overview", &with, "")).await;
        assert_eq!(r.status, 401);
        let still = [HOST, (SESSION, ck2.as_str())];
        assert_eq!(
            ui.request(req("GET", "/api/overview", &still, ""))
                .await
                .status,
            200
        );
        // The deleted token no longer logs in.
        assert_eq!(sign_in(&ui, &token).await.status, 401);
    }

    #[tokio::test]
    async fn the_flag_token_logs_in_whole_and_only_whole() {
        let d = tempfile::tempdir().unwrap();
        let c = center(d.path());
        let ui = Ui::new(&c, Some("from-the-flag".into()), true);
        let r = sign_in(&ui, "from-the-flag").await;
        assert_eq!(r.status, 200);
        // Its session lives although no stored token backs it.
        let ck = session_token(&r);
        let r = ui
            .request(req("GET", "/api/overview", &[HOST, (SESSION, &ck)], ""))
            .await;
        assert_eq!(r.status, 200);
        assert_eq!(sign_in(&ui, "from-the-fla").await.status, 401);
        assert_eq!(sign_in(&ui, "from-the-flag-and-more").await.status, 401);
    }

    #[tokio::test]
    async fn with_the_login_off_a_token_changes_nothing() {
        let d = tempfile::tempdir().unwrap();
        let ui = Ui::new(&center(d.path()), Some(TOKEN.into()), false);
        let h = ("Host", "127.0.0.1:7480");
        let r = ui.request(req("GET", "/login", &[h], "")).await;
        assert_eq!((r.status, header(&r, "Location")), (303, Some("/")));
        let r = ui
            .request(req("POST", "/login", &[h], &format!("token={TOKEN}")))
            .await;
        assert_eq!((r.status, header(&r, "Location")), (303, Some("/")));
        let r = ui.request(req("GET", "/api/session", &[h], "")).await;
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(
            (v["login"].clone(), v["logged_in"].clone()),
            (false.into(), true.into())
        );
        // Still only for this machine.
        let r = ui
            .request(req("GET", "/api/session", &[("Host", "evil.example")], ""))
            .await;
        assert_eq!(r.status, 403);
    }

    #[tokio::test]
    async fn tokens_are_shown_once_and_kept_hashed() {
        let d = tempfile::tempdir().unwrap();
        let c = center(d.path());
        let ui = Ui::new(&c, None, false);
        let h = ("Host", "localhost:7480");
        let r = ui.request(req("GET", "/api/session", &[h], "")).await;
        let ck = session_token(&r);
        let r = ui
            .request(req(
                "POST",
                "/api/tokens/create",
                &[h, (SESSION, &ck)],
                r#"{"label":"ci"}"#,
            ))
            .await;
        let token = serde_json::from_slice::<Value>(&r.body).unwrap()["token"]
            .as_str()
            .unwrap()
            .to_string();
        let state = std::fs::read_to_string(d.path().join(crate::store::FILE)).unwrap();
        assert!(!state.contains(&token));
        assert!(state.contains(&util::sha256_hex(token.as_bytes())));
    }

    // ---- The log ----

    /// A GET with a query string.
    fn get(path: &str, query: &str, headers: &[(&str, &str)]) -> Request {
        let mut r = req("GET", path, headers, "");
        r.query = query.to_string();
        r
    }

    /// A center with a UI that needs no login, a session for it, and a log
    /// with a few nodes' entries in it.
    async fn with_a_log(dir: &std::path::Path) -> (Center, Arc<Ui>, String) {
        let c = center(dir);
        let ui = Ui::new(&c, None, false);
        let session = ui
            .request(req(
                "GET",
                "/api/session",
                &[("Host", "127.0.0.1:7480")],
                "",
            ))
            .await;
        let cookie = session_token(&session);
        let log = c.log();
        log.set_level(Level::Debug);
        log.record(Level::Info, None, "nerve-center started");
        log.record(
            Level::Info,
            Some(("alpha", "n1")),
            "link up (node software x.y.z)",
        );
        log.record(
            Level::Warn,
            Some(("alpha", "n1")),
            "link dropped: the connection closed without a bye",
        );
        log.record(
            Level::Info,
            Some(("beta", "n2")),
            "link up (node software x.y.z)",
        );
        log.record(Level::Error, None, "cannot write the state file: disk full");
        log.record(
            Level::Debug,
            Some(("beta", "n2")),
            "the node's description changed",
        );
        (c, ui, cookie)
    }

    async fn log_view(ui: &Ui, cookie: &str, query: &str) -> Value {
        let r = ui
            .request(get(
                "/api/log",
                query,
                &[("Host", "127.0.0.1:7480"), (SESSION, cookie)],
            ))
            .await;
        assert_eq!(r.status, 200, "{query}: {}", body(&r));
        json(&r)
    }

    fn texts(v: &Value) -> Vec<&str> {
        v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["msg"].as_str().unwrap())
            .collect()
    }

    #[tokio::test]
    async fn the_log_page_has_its_lists_and_nothing_native() {
        let d = tempfile::tempdir().unwrap();
        let (_c, ui, ck) = with_a_log(d.path()).await;
        let h = ("Host", "127.0.0.1:7480");
        let index = ui.request(req("GET", "/", &[h, (SESSION, &ck)], "")).await;
        let index = body(&index);
        assert!(index.contains("href=\"#log\""), "no Log tab in the menu");
        let js = ui
            .request(req("GET", "/app.js", &[h, (SESSION, &ck)], ""))
            .await;
        let js = body(&js);
        // The level and the machine are picked from lists of the page's own, a
        // button and a search field, as the statistics page does; the file is
        // a link to the download.
        for part in [
            "pageLog",
            "logLevelPicker",
            "logNodePicker",
            "\"/api/log\"",
            "/api/log/download",
            "role: \"combobox\"",
            "\"Errors only\"",
            "\"The center itself\"",
        ] {
            assert!(js.contains(part), "the page has no {part}");
        }
        assert!(!js.contains("createElement(\"select\")") && !js.contains("el(\"select\""));
        assert!(!index.contains("<select"));
        // The level of the center is chosen from a list too, in the settings.
        assert!(js.contains("levelPicker") && js.contains("log_level"));
    }

    #[tokio::test]
    async fn the_log_view_is_newest_first_and_filters_by_level_node_and_text() {
        let d = tempfile::tempdir().unwrap();
        let (_c, ui, ck) = with_a_log(d.path()).await;
        let all = log_view(&ui, &ck, "").await;
        // The center's startup line is first made; the newest comes first.
        let t = texts(&all);
        assert_eq!(t.len(), 6, "{t:?}");
        assert_eq!(t[0], "the node's description changed");
        assert_eq!(t[5], "nerve-center started");
        let first = &all["entries"][0];
        assert_eq!(first["level"], "debug");
        assert_eq!(first["node"], "beta");
        assert_eq!(first["node_id"], "n2");
        assert!(first["ts"].as_u64().unwrap() > 0 && first["seq"].as_u64().unwrap() > 0);
        assert_eq!(all["level"], "debug");
        assert_eq!(all["file"], true);
        // The machines that can be picked: those the log knows about.
        assert_eq!(
            all["nodes"],
            json!([
                {"id": "n1", "name": "alpha", "paired": false},
                {"id": "n2", "name": "beta", "paired": false},
            ])
        );
        // The level is the least severe shown.
        let warn = log_view(&ui, &ck, "level=warn").await;
        assert_eq!(
            texts(&warn),
            [
                "cannot write the state file: disk full",
                "link dropped: the connection closed without a bye"
            ]
        );
        assert_eq!(texts(&log_view(&ui, &ck, "level=error").await).len(), 1);
        assert_eq!(texts(&log_view(&ui, &ck, "level=INFO").await).len(), 5);
        // A machine by its id; `-` is what is about none.
        let beta = log_view(&ui, &ck, "node=n2").await;
        assert_eq!(texts(&beta).len(), 2);
        let center_only = log_view(&ui, &ck, "node=-").await;
        assert_eq!(
            texts(&center_only),
            [
                "cannot write the state file: disk full",
                "nerve-center started"
            ]
        );
        // Text in the message or the machine's name, in any letter case.
        assert_eq!(texts(&log_view(&ui, &ck, "q=DROPPED").await).len(), 1);
        assert_eq!(texts(&log_view(&ui, &ck, "q=alpha").await).len(), 2);
        // Percent-escapes are read: a space and a colon.
        assert_eq!(
            texts(&log_view(&ui, &ck, "q=state%20file%3A").await).len(),
            1
        );
        // All of them at once.
        let both = log_view(&ui, &ck, "level=warn&node=n1&q=link").await;
        assert_eq!(
            texts(&both),
            ["link dropped: the connection closed without a bye"]
        );
        assert!(texts(&log_view(&ui, &ck, "node=nobody").await).is_empty());
        assert_eq!(texts(&log_view(&ui, &ck, "limit=2").await).len(), 2);
    }

    #[tokio::test]
    async fn a_live_view_asks_for_what_came_after() {
        let d = tempfile::tempdir().unwrap();
        let (c, ui, ck) = with_a_log(d.path()).await;
        let seen = log_view(&ui, &ck, "").await;
        let last = seen["entries"][0]["seq"].as_u64().unwrap();
        assert!(texts(&log_view(&ui, &ck, &format!("after={last}")).await).is_empty());
        c.note(Level::Warn, Some("n1"), "link dropped again");
        c.log().record(Level::Info, None, "something else");
        let more = log_view(&ui, &ck, &format!("after={last}")).await;
        assert_eq!(texts(&more), ["something else", "link dropped again"]);
        // The entries are numbered one after the other.
        let seqs: Vec<u64> = more["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["seq"].as_u64().unwrap())
            .collect();
        assert_eq!(seqs, [last + 2, last + 1]);
    }

    #[tokio::test]
    async fn the_log_view_refuses_what_it_cannot_read() {
        let d = tempfile::tempdir().unwrap();
        let (_c, ui, ck) = with_a_log(d.path()).await;
        for q in ["level=loud", "after=x", "limit=-1", "after=1.5"] {
            let r = ui
                .request(get(
                    "/api/log",
                    q,
                    &[("Host", "127.0.0.1:7480"), (SESSION, &ck)],
                ))
                .await;
            assert_eq!(r.status, 400, "{q}");
            assert!(json(&r)["error"].as_str().unwrap().len() > 5);
        }
        // Like every other API, the log is for a signed-in browser.
        let locked = locked(d.path());
        for path in ["/api/log", "/api/log/download"] {
            let r = locked.request(get(path, "", &[HOST])).await;
            assert_eq!(r.status, 401, "{path}");
        }
    }

    #[tokio::test]
    async fn the_download_is_the_log_file() {
        let d = tempfile::tempdir().unwrap();
        let (_c, ui, ck) = with_a_log(d.path()).await;
        let r = ui
            .request(get(
                "/api/log/download",
                "",
                &[("Host", "127.0.0.1:7480"), (SESSION, &ck)],
            ))
            .await;
        assert_eq!(r.status, 200);
        assert_eq!(header(&r, "Content-Type"), Some("application/x-ndjson"));
        assert_eq!(
            header(&r, "Content-Disposition"),
            Some("attachment; filename=\"nerve-center-log.jsonl\"")
        );
        // The same lines as the file, each an entry, the oldest first.
        let file = std::fs::read(d.path().join("log.jsonl")).unwrap();
        assert_eq!(r.body, file);
        let lines: Vec<Value> = body(&r)
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 6);
        assert_eq!(lines[0]["msg"], "nerve-center started");
        assert_eq!(lines[2]["level"], "warn");
        assert_eq!(lines[2]["node"], "alpha");
    }

    #[tokio::test]
    async fn the_log_level_is_set_in_the_center_settings() {
        let d = tempfile::tempdir().unwrap();
        let c = center(d.path());
        let ui = Ui::new(&c, None, false);
        let got = center_settings(&ui, None).await.unwrap();
        assert_eq!(got["log_level"], "info");
        assert_eq!(got["log_level_pinned"], false);
        center_settings(&ui, Some(json!({"log_level": "debug"})))
            .await
            .unwrap();
        assert_eq!(
            center_settings(&ui, None).await.unwrap()["log_level"],
            "debug"
        );
        assert_eq!(c.log().level(), Level::Debug);
        // A level that is none, or a refused save, changes nothing.
        for bad_level in [json!("loud"), json!(3), json!(true)] {
            let (status, body) = center_settings(
                &ui,
                Some(json!({"name": "other", "log_level": bad_level.clone()})),
            )
            .await
            .unwrap_err();
            assert_eq!(status, 400, "{bad_level}");
            assert!(
                body["error"]
                    .as_str()
                    .unwrap()
                    .contains("error, warn, info or debug")
            );
        }
        let got = center_settings(&ui, None).await.unwrap();
        assert_eq!(
            (got["log_level"].as_str(), got["name"].as_str()),
            (Some("debug"), Some("test"))
        );
        // A save without it leaves it, and the log says what was saved.
        center_settings(&ui, Some(json!({"retention_days": 5})))
            .await
            .unwrap();
        assert_eq!(c.log().level(), Level::Debug);
        let v = c.log_json(&Query {
            limit: 100,
            ..Query::default()
        });
        let t: Vec<&str> = texts(&v);
        assert!(
            t.contains(&"the log level changes from info to debug"),
            "{t:?}"
        );
        assert!(
            t.contains(&"the center settings were saved (statistics retention)"),
            "{t:?}"
        );
        // The same values again are no change and no line; a new name is one.
        center_settings(
            &ui,
            Some(json!({"retention_days": 5, "name": "test", "log_level": "debug"})),
        )
        .await
        .unwrap();
        center_settings(&ui, Some(json!({"name": "renamed"})))
            .await
            .unwrap();
        let v = c.log_json(&Query {
            limit: 100,
            ..Query::default()
        });
        let saved: Vec<&str> = texts(&v)
            .into_iter()
            .filter(|t| t.starts_with("the center settings were saved"))
            .collect();
        assert_eq!(
            saved,
            [
                "the center settings were saved (name)",
                "the center settings were saved (statistics retention)"
            ]
        );
    }

    /// Saving another setting while `--log` holds the level must not store the
    /// flag's level as the owner's: the page shows and sends the stored one.
    #[tokio::test]
    async fn saving_a_setting_under_the_flag_leaves_the_stored_level_alone() {
        let d = tempfile::tempdir().unwrap();
        center(d.path()).set_log_level(Level::Debug);
        let c = Center::open(crate::center::Options {
            state_dir: d.path().to_path_buf(),
            name: Some("test".into()),
            public_url: "http://127.0.0.1:1".into(),
            log: None,
            log_level: Some(Level::Warn),
        })
        .unwrap();
        let ui = Ui::new(&c, None, false);
        let got = center_settings(&ui, None).await.unwrap();
        assert_eq!(got["log_level"], "debug");
        assert_eq!(got["log_level_now"], "warn");
        assert_eq!(got["log_level_pinned"], true);
        // What the page does: sends every field, the level it was given.
        center_settings(
            &ui,
            Some(json!({"name": "renamed", "retention_days": 30, "log_level": got["log_level"]})),
        )
        .await
        .unwrap();
        assert_eq!(c.stored_log_level(), Level::Debug);
        assert_eq!(c.log().level(), Level::Warn);
        drop(c);
        // The next start without the flag runs at the level the owner set.
        assert_eq!(center(d.path()).log().level(), Level::Debug);
    }

    #[tokio::test]
    async fn the_ui_logs_who_gets_in_and_leaves_every_secret_out() {
        let d = tempfile::tempdir().unwrap();
        let c = center(d.path());
        let ui = Ui::new(&c, Some(TOKEN.into()), true);
        // A wrong token is told, and what was typed is not.
        let r = sign_in(&ui, "typo-of-nrv_test-token-lon").await;
        assert_eq!(r.status, 401);
        let r = sign_in(&ui, TOKEN).await;
        assert_eq!(r.status, 200);
        let ck = session_token(&r);
        // A token made in the UI is shown to the browser once; it and its
        // label's neighbours are not in the log, its label is.
        let post = |path: &'static str, b: &'static str| {
            ui.request(req("POST", path, &[HOST, (SESSION, &ck)], b))
        };
        let made = json(&post("/api/tokens/create", r#"{"label":"ci"}"#).await);
        let (id, token) = (
            made["id"].as_str().unwrap(),
            made["token"].as_str().unwrap(),
        );
        assert!(token.starts_with("nrv_"));
        let id_body: &'static str = Box::leak(format!(r#"{{"id":"{id}"}}"#).into_boxed_str());
        post("/api/tokens/delete", id_body).await;

        let v = c.log_json(&Query {
            limit: 100,
            ..Query::default()
        });
        let got = texts(&v);
        assert_eq!(
            got,
            [
                "the harness token labelled \"ci\" was deleted",
                "a harness token was made, labelled \"ci\"",
                "signed in to the web UI",
                "a web UI sign-in was refused: wrong token",
            ]
        );
        let file = std::fs::read_to_string(d.path().join("log.jsonl")).unwrap();
        for secret in [token, TOKEN, "typo-of-nrv"] {
            assert!(!file.contains(secret), "{secret} is in the file");
            assert!(!v.to_string().contains(secret), "{secret} is in the view");
        }
        // Five wrong tokens lock the sign-in; the log says so once.
        for _ in 0..LOGIN_TRIES {
            sign_in(&ui, "wrong").await;
        }
        let v = c.log_json(&Query {
            limit: 100,
            ..Query::default()
        });
        let locked = texts(&v)
            .into_iter()
            .filter(|t| t.contains("locked for a minute"))
            .count();
        assert_eq!(locked, 1);
    }

    #[tokio::test]
    async fn the_disable_switch_takes_a_boolean_and_a_known_node() {
        let d = tempfile::tempdir().unwrap();
        let c = center(d.path());
        c.update(|s| {
            s.nodes.insert(
                "n1".into(),
                crate::store::NodeRecord {
                    id: "n1".into(),
                    name: "box".into(),
                    public_key: "00".into(),
                    old_key: None,
                    key_rotations: 0,
                    platform: "linux".into(),
                    arch: "x86_64".into(),
                    paired_ms: 0,
                    disabled: false,
                    last_seen_ms: 0,
                    going_away: None,
                    descriptor: None,
                    catalog: Default::default(),
                },
            );
        });
        let ui = Ui::new(&c, None, false);
        let h = ("Host", "127.0.0.1:7480");
        let r = ui.request(req("GET", "/api/session", &[h], "")).await;
        let ck = session_token(&r);
        let post = |body: &'static str| {
            ui.request(req(
                "POST",
                "/api/nodes/disable",
                &[h, (SESSION, &ck)],
                body,
            ))
        };
        let json = |r: &Response| serde_json::from_slice::<Value>(&r.body).unwrap();

        // A missing or non-boolean flag is refused and changes nothing.
        for b in [
            r#"{"id":"n1"}"#,
            r#"{"id":"n1","disabled":"true"}"#,
            r#"{"id":"n1","disabled":1}"#,
        ] {
            let r = post(b).await;
            assert_eq!(r.status, 400, "{b}");
            assert!(
                json(&r)["error"]
                    .as_str()
                    .unwrap()
                    .contains("true or false")
            );
        }
        assert_eq!(c.nodes_json()[0]["disabled"], false);

        // An unknown node is a 404 with a text.
        let r = post(r#"{"id":"nope","disabled":true}"#).await;
        assert_eq!(r.status, 404);
        assert_eq!(json(&r)["error"], "no such node");

        // The answer is the new state, and the overview shows it.
        let r = post(r#"{"id":"n1","disabled":true}"#).await;
        assert_eq!(r.status, 200);
        assert_eq!(json(&r), json!({"disabled": true}));
        assert_eq!(c.nodes_json()[0]["disabled"], true);
        let r = post(r#"{"id":"n1","disabled":false}"#).await;
        assert_eq!(json(&r), json!({"disabled": false}));
        assert_eq!(c.nodes_json()[0]["disabled"], false);
    }

    /// No script of the center's page builds HTML from text: what a node
    /// wrote goes into text nodes only, and the page's session is readable
    /// by its scripts. The page has no inline script.
    #[test]
    fn the_page_builds_no_html_from_text() {
        assert_eq!(
            nerve_transport::webui::html_sinks(APP_JS),
            Vec::<&str>::new()
        );
        for line in INDEX.lines().filter(|l| l.contains("<script")) {
            assert!(line.contains(" src=\""), "an inline script: {line}");
        }
        let handler = INDEX
            .split_whitespace()
            .find(|w| w.starts_with("on") && w.contains('='));
        assert_eq!(handler, None, "an inline handler");
    }
}
