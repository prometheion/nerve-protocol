//! What the web UIs of the center and the node share: the security headers,
//! the `Host` and `Origin` checks, the session a page holds in its tab, the
//! delay on a wrong secret ([`WrongSecrets`]), and the pages themselves: the
//! built web UIs of `webui/` ([`DIST`]), served as they were built, the login
//! page and both UIs' pages and assets.
//!
//! A session is a random token the login answers with. The page keeps it in
//! its tab's `sessionStorage` and sends it as [`SESSION_HEADER`] with every
//! API call; there is no cookie. A browser keeps a cookie per host, not per
//! port, and sends it to every port of that host: a program that listens on
//! another `localhost` port of the owner's machine would get the session.
//! A header is sent only by the page's own script, and another origin can
//! neither read the token nor send the header without a CORS preflight,
//! which these servers do not answer; so no CSRF token is needed either.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

use crate::http::{Request, Response};

include!(concat!(env!("OUT_DIR"), "/webui_dist.rs"));

/// The git ref of the user guide the program's help links to: the release's
/// tag in a release build, `main` in any other (build.rs).
pub const GUIDE_REF: &str = env!("NERVE_GUIDE_REF");

/// Which web UI a page is: each has its own page, and both share the login
/// and the assets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ui {
    Center,
    Node,
}

/// The built file at `path` of `webui/dist`.
pub fn dist_file(path: &str) -> Option<&'static [u8]> {
    DIST.iter().find(|(p, _)| *p == path).map(|(_, b)| *b)
}

/// The type a browser is told for a file of the built web UIs.
fn content_type(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, e)| e) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

/// The header that carries a page's session (lowercase, as
/// [`Request::header`] takes it).
pub const SESSION_HEADER: &str = "x-nerve-session";
/// How long a session lasts.
pub const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
/// What a wrong secret at the login costs: a guess takes this long, and the
/// log and the CPU stay small.
pub const WRONG_SECRET_DELAY: Duration = Duration::from_millis(300);
/// Wrong secrets whose answer waits [`WRONG_SECRET_DELAY`], at once. Past
/// this many, the one that waited longest is answered at once.
pub const LATE: usize = 128;

/// The wrong secrets of a login: each one's answer waits, and they are told
/// in the log once a minute. A wrong secret never locks the login: a lock
/// that counts every caller's tries could be kept shut by any process that
/// reaches the port, the owner's login included. A waiting answer should
/// hold no connection slot and no place of its peer (the caller gives them
/// back first): a peer that posts wrong secrets as fast as it can would fill
/// both. The line of waiting answers is bounded by [`LATE`] instead.
#[derive(Debug, Default)]
pub struct WrongSecrets {
    /// Wrong secrets since the last line about them, and when that was.
    told: Mutex<(u32, Option<Instant>)>,
    /// The answers that wait, the oldest first.
    late: Mutex<VecDeque<Arc<Notify>>>,
}

impl WrongSecrets {
    /// Counts a wrong secret, and says how many to tell in the log: the
    /// first of a minute at once, the rest when the next comes after it.
    pub fn note(&self) -> Option<u32> {
        let mut w = crate::sync::lock(&self.told);
        w.0 += 1;
        match w.1 {
            Some(t) if t.elapsed() < Duration::from_secs(60) => None,
            _ => {
                let n = w.0;
                *w = (0, Some(Instant::now()));
                Some(n)
            }
        }
    }

    /// Waits [`WRONG_SECRET_DELAY`] before a wrong secret is answered, or
    /// less when [`LATE`] others wait and this one waited longest.
    pub async fn wait(&self) {
        let me = Arc::new(Notify::new());
        {
            let mut late = self.late_line();
            if late.len() >= LATE
                && let Some(oldest) = late.pop_front()
            {
                oldest.notify_one();
            }
            late.push_back(me.clone());
        }
        let _gone = Late {
            of: self,
            me: me.clone(),
        };
        tokio::select! {
            _ = tokio::time::sleep(WRONG_SECRET_DELAY) => {}
            _ = me.notified() => {}
        }
    }

    /// How many answers wait now.
    pub fn waiting(&self) -> usize {
        self.late_line().len()
    }

    /// Makes the last line about wrong secrets older, for a test.
    #[doc(hidden)]
    pub fn age(&self, by: Duration) {
        let mut w = crate::sync::lock(&self.told);
        w.1 = w.1.and_then(|t| t.checked_sub(by));
    }

    fn late_line(&self) -> std::sync::MutexGuard<'_, VecDeque<Arc<Notify>>> {
        crate::sync::lock(&self.late)
    }
}

/// A wrong secret's wait, which leaves the line when it ends.
struct Late<'a> {
    of: &'a WrongSecrets,
    me: Arc<Notify>,
}

impl Drop for Late<'_> {
    fn drop(&mut self) {
        self.of.late_line().retain(|n| !Arc::ptr_eq(n, &self.me));
    }
}

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

    #[track_caller]
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Session>> {
        crate::sync::lock(&self.map)
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

/// The asset of both UIs at `path`, if it is one: a script, a stylesheet or
/// an image of the built web UIs (their names hold a hash of their
/// content), and the icon. A built page is no asset: each is served at its
/// own path ([`page`], [`login_page`]).
pub fn asset(path: &str) -> Option<Response> {
    let rel = path.strip_prefix('/')?;
    if rel.ends_with(".html") || rel.contains("..") {
        return None;
    }
    let body = dist_file(rel)?;
    Some(Response::new(200, content_type(rel), body))
}

/// A UI's page, with the ref of the user guide its help links to.
pub fn page(ui: Ui) -> Response {
    let name = match ui {
        Ui::Center => "center.html",
        Ui::Node => "node.html",
    };
    let html = String::from_utf8_lossy(dist_file(name).unwrap_or_default())
        .replace("{{GUIDE_REF}}", &attr(GUIDE_REF));
    Response::new(200, "text/html; charset=utf-8", html)
}

/// What the login page says: what is asked for (`secret`), its title and
/// line, and the command that shows the secret, with what follows it.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct LoginText<'a> {
    pub secret: &'a str,
    pub title: &'a str,
    pub tagline: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<&'a str>,
    pub after: &'a str,
}

/// The login page. Its words go into the page as data (a `<meta>` the page
/// reads), never as markup.
pub fn login_page(text: &LoginText) -> Response {
    let json = serde_json::to_string(text).unwrap_or_default();
    let html = String::from_utf8_lossy(dist_file("login.html").unwrap_or_default())
        .replace("{{LOGIN}}", &attr(&json));
    Response::new(200, "text/html; charset=utf-8", html)
}

/// `text` for an attribute between double quotes.
fn attr(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
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

/// The name of a `Host` header, without its port.
fn host_name(h: &str) -> &str {
    if let Some(rest) = h.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        h.rsplit_once(':').map(|(n, _)| n).unwrap_or(h)
    }
}

/// Whether a `Host` header names loopback.
pub fn host_is_loopback(host: Option<&str>) -> bool {
    let Some(h) = host else { return false };
    matches!(
        host_name(h).to_ascii_lowercase().as_str(),
        "127.0.0.1" | "localhost" | "::1"
    )
}

/// Whether a `Host` header is the address `ip` itself, written as a number:
/// a server on another loopback address than 127.0.0.1 is reached so, and
/// no page of another name (DNS rebinding) sends it.
pub fn host_is_address(host: Option<&str>, ip: std::net::IpAddr) -> bool {
    host.and_then(|h| host_name(h).parse::<std::net::IpAddr>().ok())
        .is_some_and(|a| a.to_canonical() == ip.to_canonical())
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
    fn a_host_is_an_address_only_as_a_number() {
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        assert!(host_is_address(Some("127.0.0.2:7470"), ip("127.0.0.2")));
        assert!(host_is_address(Some("[::1]:7470"), ip("::1")));
        assert!(host_is_address(
            Some("127.0.0.2:7470"),
            ip("::ffff:127.0.0.2")
        ));
        for h in ["127.0.0.3:7470", "localhost:7470", "127.0.0.2.evil.example"] {
            assert!(!host_is_address(Some(h), ip("127.0.0.2")), "{h}");
        }
        assert!(!host_is_address(None, ip("127.0.0.2")));
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

    fn header(r: &Response, n: &str) -> Option<String> {
        r.headers
            .iter()
            .find(|(k, _)| k == n)
            .map(|(_, v)| v.clone())
    }

    /// The built web UIs are embedded whole, and each asset is served with
    /// its type, which `nosniff` makes the browser keep to: a script as a
    /// script, a stylesheet as one. A built page is not an asset, and no
    /// path climbs out of the folder.
    #[test]
    fn every_asset_is_served_with_its_type() {
        for page in ["center.html", "node.html", "login.html", "icon.svg"] {
            assert!(dist_file(page).is_some(), "{page} is not built");
        }
        let mut kinds = 0;
        for (path, body) in DIST {
            let r = asset(&format!("/{path}"));
            if path.ends_with(".html") {
                assert!(r.is_none(), "{path} is served as an asset");
                continue;
            }
            let r = r.unwrap_or_else(|| panic!("{path} is not served"));
            assert_eq!(r.status, 200);
            assert_eq!(&r.body, body);
            let kind = header(&r, "Content-Type").unwrap();
            let want = match path.rsplit_once('.').unwrap().1 {
                "js" => "text/javascript; charset=utf-8",
                "css" => "text/css; charset=utf-8",
                "svg" => "image/svg+xml",
                other => panic!("{path}: a file of type {other} in the build"),
            };
            assert_eq!(kind, want, "{path}");
            kinds += 1;
        }
        assert!(kinds >= 3, "{kinds}");
        for path in [
            "/center.html",
            "/assets/../center.html",
            "/nothing.js",
            "assets/x.js",
            "/",
        ] {
            assert!(asset(path).is_none(), "{path}");
        }
    }

    /// The CSP allows no inline script or style: every page loads its
    /// scripts and styles as files of the build, and holds none itself.
    #[test]
    fn the_pages_load_only_files_of_the_build() {
        for page in ["center.html", "node.html", "login.html"] {
            let html = String::from_utf8(dist_file(page).unwrap().to_vec()).unwrap();
            assert!(!html.contains("<style"), "{page}: an inline style");
            assert!(!html.contains(" style="), "{page}: a style attribute");
            let lower = html.to_ascii_lowercase();
            for (i, _) in lower.match_indices("<script") {
                let tag = &html[i..i + html[i..].find('>').unwrap()];
                assert!(
                    tag.contains(" src=\"/assets/"),
                    "{page}: an inline script: {tag}"
                );
                assert!(
                    html[i..].starts_with(&format!("{tag}></script>")),
                    "{page}: {tag}"
                );
            }
            let handler = lower
                .split(|c: char| c.is_whitespace() || c == '<')
                .find(|w| w.starts_with("on") && w.contains('='));
            assert_eq!(handler, None, "{page}: an inline handler");
            for attr in [" src=\"/", " href=\"/"] {
                for (i, _) in html.match_indices(attr) {
                    let from = i + attr.len();
                    let file = &html[from..from + html[from..].find('"').unwrap()];
                    assert!(
                        dist_file(file).is_some(),
                        "{page} loads {file}, which is not built"
                    );
                }
            }
        }
    }

    /// The help's guide links name the docs of this release, at its tag,
    /// when it is a release build, and `main` in any other build: a tag
    /// that does not exist yet would be a dead link. The page says it in a
    /// `<meta>` its script reads.
    #[test]
    fn the_guide_is_the_one_of_this_release() {
        assert!(
            GUIDE_REF == "main" || GUIDE_REF == concat!("v", env!("CARGO_PKG_VERSION")),
            "{GUIDE_REF}"
        );
        for ui in [Ui::Center, Ui::Node] {
            let r = page(ui);
            assert_eq!(
                header(&r, "Content-Type").unwrap(),
                "text/html; charset=utf-8"
            );
            let html = String::from_utf8(r.body).unwrap();
            assert!(
                html.contains(&format!(
                    "<meta name=\"nerve-guide\" content=\"{GUIDE_REF}\">"
                )),
                "{html}"
            );
            assert!(!html.contains("{{"), "{html}");
        }
        assert!(
            String::from_utf8(page(Ui::Center).body)
                .unwrap()
                .contains("Nerve center")
        );
        assert!(
            String::from_utf8(page(Ui::Node).body)
                .unwrap()
                .contains("Nerve node")
        );
    }

    /// The login's words go into the page as data: a folder name with a
    /// quote or markup in it ends up as text, never as an element.
    #[test]
    fn the_login_says_its_words_as_data() {
        let text = LoginText {
            secret: "Owner token",
            title: "Log in to this center",
            tagline: "One center\"><script>x</script> for all",
            command: Some("nerve-center owner-token --state-dir '/srv/a&b'"),
            after: " shows it.",
        };
        let html = String::from_utf8(login_page(&text).body).unwrap();
        assert!(!html.contains("<script>x"), "{html}");
        assert!(!html.contains("{{LOGIN}}"), "{html}");
        let at = html.find("<meta name=\"nerve-login\" content=\"").unwrap() + 34;
        let content = &html[at..at + html[at..].find('"').unwrap()];
        let back = content
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&");
        let v: serde_json::Value = serde_json::from_str(&back).unwrap();
        assert_eq!(v["tagline"], text.tagline);
        assert_eq!(v["command"], text.command.unwrap());
        assert_eq!(v["secret"], "Owner token");
    }

    #[test]
    fn wrong_secrets_are_told_once_a_minute() {
        let w = WrongSecrets::default();
        assert_eq!(w.note(), Some(1));
        for _ in 0..50 {
            assert_eq!(w.note(), None);
        }
        // A minute later the count of what came meanwhile is told.
        w.age(Duration::from_secs(61));
        assert_eq!(w.note(), Some(51));
    }

    /// A wrong secret's answer waits; past [`LATE`] waiting, the one that
    /// waited longest goes at once, so the waits hold a bounded number of
    /// connections.
    #[tokio::test]
    async fn a_wrong_secret_waits_and_past_the_limit_the_oldest_goes_first() {
        let w = Arc::new(WrongSecrets::default());
        let start = Instant::now();
        w.wait().await;
        assert!(start.elapsed() >= WRONG_SECRET_DELAY);
        assert_eq!(w.waiting(), 0);
        let waits: Vec<_> = (0..LATE)
            .map(|_| {
                let w = w.clone();
                tokio::spawn(async move { w.wait().await })
            })
            .collect();
        while w.waiting() < LATE {
            tokio::task::yield_now().await;
        }
        let extra = {
            let w = w.clone();
            tokio::spawn(async move { w.wait().await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(waits[0].is_finished(), "the oldest still waits");
        assert_eq!(waits.iter().filter(|w| w.is_finished()).count(), 1);
        assert_eq!(w.waiting(), LATE);
        for t in waits {
            t.await.unwrap();
        }
        extra.await.unwrap();
        assert_eq!(w.waiting(), 0);
    }
}
