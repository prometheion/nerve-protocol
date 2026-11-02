//! What the web UIs of the center and the node share: the security headers,
//! the `Host` and `Origin` checks, the session a page holds in its tab, the
//! delay on a wrong secret, the login page, and the assets both pages load
//! (the stylesheet, the theme script, the icon and `kit.js`, the helpers of
//! both pages' scripts).
//!
//! A session is a random token the login answers with. The page keeps it in
//! its tab's `sessionStorage` and sends it as [`SESSION_HEADER`] with every
//! API call; there is no cookie. A browser keeps a cookie per host, not per
//! port, and sends it to every port of that host: a program that listens on
//! another `localhost` port of the owner's machine would get the session.
//! A header is sent only by the page's own script, and another origin can
//! neither read the token nor send the header without a CORS preflight,
//! which these servers do not answer; so no CSRF token is needed either.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::http::{Request, Response};

pub const APP_CSS: &str = include_str!("webui/app.css");
pub const THEME_JS: &str = include_str!("webui/theme-init.js");
pub const ICON: &str = include_str!("webui/icon.svg");
pub const KIT_JS: &str = include_str!("webui/kit.js");
pub const LOGIN: &str = include_str!("webui/login.html");
pub const LOGIN_JS: &str = include_str!("webui/login.js");

/// The header that carries a page's session (lowercase, as
/// [`Request::header`] takes it).
pub const SESSION_HEADER: &str = "x-nerve-session";
/// How long a session lasts.
pub const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
/// What a wrong secret at the login costs: a guess takes this long, and the
/// log and the CPU stay small.
pub const WRONG_SECRET_DELAY: Duration = Duration::from_millis(300);

/// One page's session.
#[derive(Debug, Clone)]
pub struct Session {
    created: Instant,
    /// SHA-256 (hex) of the secret that logged in; none without a login.
    pub via: Option<String>,
}

/// The sessions of a UI, in memory only: a restart ends them all.
#[derive(Debug, Default)]
pub struct Sessions {
    map: Mutex<HashMap<String, Session>>,
}

impl Sessions {
    pub fn new() -> Sessions {
        Sessions::default()
    }

    /// Starts a session and gives its token; `via` is the SHA-256 (hex) of
    /// the secret that logged in.
    pub fn start(&self, via: Option<String>) -> String {
        let token = crate::keys::random_token(32);
        self.lock().insert(
            token.clone(),
            Session {
                created: Instant::now(),
                via,
            },
        );
        token
    }

    /// The session `req` names in its [`SESSION_HEADER`], with its token.
    /// Expired sessions are swept here, when a request comes in, not on a
    /// timer. A cookie is never read.
    pub fn of(&self, req: &Request) -> Option<(String, Session)> {
        let token = req.header(SESSION_HEADER).filter(|t| !t.is_empty())?;
        let mut map = self.lock();
        map.retain(|_, s| s.created.elapsed() < SESSION_TTL);
        map.get(token).map(|s| (token.to_string(), s.clone()))
    }

    pub fn end(&self, token: &str) {
        self.lock().remove(token);
    }

    /// Ends the sessions `keep` says no to.
    pub fn retain(&self, mut keep: impl FnMut(&Session) -> bool) {
        self.lock().retain(|_, s| keep(s));
    }

    pub fn end_all(&self) {
        self.lock().clear();
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Session>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Makes a session older, for a test of its end.
    #[doc(hidden)]
    pub fn age(&self, token: &str, by: Duration) {
        if let Some(s) = self.lock().get_mut(token)
            && let Some(t) = s.created.checked_sub(by)
        {
            s.created = t;
        }
    }
}

/// The asset of both UIs at `path`, if it is one.
pub fn asset(path: &str) -> Option<Response> {
    let (kind, body) = match path {
        "/app.css" => ("text/css; charset=utf-8", APP_CSS),
        "/theme-init.js" => ("text/javascript; charset=utf-8", THEME_JS),
        "/kit.js" => ("text/javascript; charset=utf-8", KIT_JS),
        "/login.js" => ("text/javascript; charset=utf-8", LOGIN_JS),
        "/icon.svg" => ("image/svg+xml", ICON),
        _ => return None,
    };
    Some(Response::new(200, kind, body))
}

/// The login page: `secret` names what is asked for, `tagline` is the line
/// under the name.
pub fn login_page(secret: &str, tagline: &str) -> Response {
    let page = LOGIN
        .replace("{{SECRET}}", secret)
        .replace("{{TAGLINE}}", tagline);
    Response::new(200, "text/html; charset=utf-8", page)
}

/// The secret a login posted, as JSON (`{"token": …}`, what the login page
/// sends) or as a form. A pasted secret often carries a trailing newline or
/// space.
pub fn posted_secret(req: &Request) -> String {
    let json = req
        .header("content-type")
        .is_some_and(|t| t.starts_with("application/json"));
    let given = if json {
        serde_json::from_slice::<serde_json::Value>(&req.body)
            .ok()
            .and_then(|v| v["token"].as_str().map(str::to_string))
    } else {
        req.form_param("token")
    };
    given.unwrap_or_default().trim().to_string()
}

pub fn see_other(to: &str) -> Response {
    Response::new(303, "text/plain; charset=utf-8", Vec::new()).with_header("Location", to)
}

/// Whether a `Host` header names loopback.
pub fn host_is_loopback(host: Option<&str>) -> bool {
    let Some(h) = host else { return false };
    let name = if let Some(rest) = h.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        h.rsplit_once(':').map(|(n, _)| n).unwrap_or(h)
    };
    matches!(
        name.to_ascii_lowercase().as_str(),
        "127.0.0.1" | "localhost" | "::1"
    )
}

/// Whether an `Origin` names the host the request was sent to.
pub fn origin_matches(origin: &str, host: Option<&str>) -> bool {
    let Some(host) = host else { return false };
    let rest = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
        .unwrap_or("");
    rest.eq_ignore_ascii_case(host)
}

/// The headers of every answer. `Referrer-Policy: no-referrer` would make a
/// browser send `Origin: null` with a post, which the origin check refuses;
/// `same-origin` sends the real origin to this server and nothing elsewhere.
/// No worker may be started and nothing fetched from elsewhere. An API
/// answer is not kept by any cache.
pub fn with_security_headers(r: Response, api: bool) -> Response {
    let r = r
        .with_header("X-Frame-Options", "DENY")
        .with_header("X-Content-Type-Options", "nosniff")
        .with_header("Referrer-Policy", "same-origin")
        .with_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; connect-src 'self'; worker-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        );
    if api {
        r.with_header("Cache-Control", "no-store")
    } else {
        r
    }
}

/// The lines of a script that write markup, for the tests that keep every
/// text of the pages in text nodes.
pub fn html_sinks(js: &str) -> Vec<&str> {
    const SINKS: [&str; 5] = [
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "srcdoc",
    ];
    js.lines()
        .filter(|l| SINKS.iter().any(|s| l.contains(s)))
        .collect()
}

/// Whether `path` is an API call's, which needs a session.
pub fn is_api(path: &str) -> bool {
    path.starts_with("/api/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn req(headers: &[(&str, &str)], body: &str) -> Request {
        let mut h = BTreeMap::new();
        for (k, v) in headers {
            h.insert(k.to_ascii_lowercase(), v.to_string());
        }
        Request {
            method: "POST".into(),
            path: "/login".into(),
            query: String::new(),
            headers: h,
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn loopback_hosts() {
        for h in [
            "127.0.0.1:7480",
            "localhost:7480",
            "LOCALHOST",
            "[::1]:7480",
        ] {
            assert!(host_is_loopback(Some(h)), "{h}");
        }
        for h in ["evil.example:7480", "127.0.0.1.evil.example", "[::2]:1"] {
            assert!(!host_is_loopback(Some(h)), "{h}");
        }
        assert!(!host_is_loopback(None));
    }

    #[test]
    fn same_origin_posts_carry_their_origin() {
        assert!(origin_matches(
            "http://127.0.0.1:7481",
            Some("127.0.0.1:7481")
        ));
        assert!(!origin_matches(
            "http://127.0.0.1:7482",
            Some("127.0.0.1:7481")
        ));
        assert!(!origin_matches("null", Some("127.0.0.1:7481")));
        assert!(!origin_matches("http://127.0.0.1:7481", None));
    }

    #[test]
    fn a_session_is_the_header_and_never_a_cookie() {
        let s = Sessions::new();
        let t = s.start(Some("ab".into()));
        assert!(s.of(&req(&[("X-Nerve-Session", &t)], "")).is_some());
        assert!(
            s.of(&req(&[("Cookie", &format!("nerve_ui={t}"))], ""))
                .is_none()
        );
        assert!(s.of(&req(&[("X-Nerve-Session", "other")], "")).is_none());
        assert!(s.of(&req(&[("X-Nerve-Session", "")], "")).is_none());
        // It ends after its time, and with `end`.
        s.age(&t, SESSION_TTL);
        assert!(s.of(&req(&[("X-Nerve-Session", &t)], "")).is_none());
        assert!(s.is_empty(), "an expired session is swept");
        let t = s.start(None);
        s.end(&t);
        assert!(s.of(&req(&[("X-Nerve-Session", &t)], "")).is_none());
    }

    #[test]
    fn the_secret_comes_as_json_or_as_a_form() {
        let j = req(
            &[("Content-Type", "application/json")],
            r#"{"token": " a b\n"}"#,
        );
        assert_eq!(posted_secret(&j), "a b");
        let f = req(
            &[("Content-Type", "application/x-www-form-urlencoded")],
            "token=x%2By",
        );
        assert_eq!(posted_secret(&f), "x+y");
        assert_eq!(posted_secret(&req(&[], "")), "");
    }

    #[test]
    fn the_headers_keep_workers_and_caches_out() {
        let r = with_security_headers(Response::text(200, "x"), true);
        let h = |n: &str| {
            r.headers
                .iter()
                .find(|(k, _)| k == n)
                .map(|(_, v)| v.clone())
        };
        let csp = h("Content-Security-Policy").unwrap();
        for part in [
            "default-src 'self'",
            "worker-src 'none'",
            "connect-src 'self'",
        ] {
            assert!(csp.contains(part), "{csp}");
        }
        assert_eq!(h("Cache-Control").as_deref(), Some("no-store"));
        let page = with_security_headers(Response::text(200, "x"), false);
        assert!(!page.headers.iter().any(|(k, _)| k == "Cache-Control"));
    }

    /// No script of the UIs builds HTML from text: what a node or a center
    /// wrote goes into text nodes only. The icons are the one place markup
    /// is set, from the fixed table at the head of kit.js.
    #[test]
    fn the_shared_script_builds_no_html_from_text() {
        assert_eq!(
            html_sinks(KIT_JS),
            vec!["  s.innerHTML = ICONS[name] || \"\";"]
        );
        assert_eq!(html_sinks(LOGIN_JS), Vec::<&str>::new());
    }
}
