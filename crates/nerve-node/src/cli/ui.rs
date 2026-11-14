//! `nerve-node ui`: the node's web UI (crate::webui, docs/dev/web-uis.md).
//! It is part of the installed node on Linux and off by default; these
//! commands turn it on and off and make, list and revoke the tokens that log
//! in to it. The running node takes each change at once, as it takes the
//! relay's. Tokens are made here only: a browser session must not be able to
//! give itself a login that outlives it.

use nerve_service::out::Page;

use super::*;

/// The address the web UI listens on unless `ui on --listen` names another.
pub const UI_ADDRESS: &str = "127.0.0.1:7470";

/// The label of the token `ui on` makes when there is none yet.
const FIRST_TOKEN: &str = "first";

/// Why there is no `ui` on Windows: the desktop app is the node's UI there
/// (#176).
pub const NO_WEB_UI_HERE: &str =
    "the node has no web UI on Windows: the desktop app is its UI there";

/// Why `ui on` is refused for a node that is not the installed one.
fn only_installed() -> String {
    format!(
        "the web UI is part of the installed node (`sudo {} install`); a node run by hand serves none",
        crate::edition::get().program
    )
}

#[derive(Debug, Subcommand)]
pub enum UiCmd {
    /// Turn the web UI on (shows a first token once)
    ///
    /// Turn the web UI on. With no token yet, makes one named `first` and shows it once. Beyond loopback it is served over TLS with a certificate of its own, made the first time; compare its fingerprint with the one the browser shows.
    On {
        /// Address and port (127.0.0.1:7470); any other address opens it to the network
        ///
        /// The address and port to listen on (127.0.0.1:7470 unless set). Any address but loopback, like 0.0.0.0:7470, makes the UI reachable from the network.
        #[arg(long, value_name = "ADDRESS")]
        listen: Option<String>,
        /// A host name for the certificate, besides this machine's own (more than once)
        ///
        /// A host name the certificate names besides this machine's own and the address; can be given more than once.
        #[arg(long = "host", value_name = "HOST")]
        names: Vec<String>,
        /// Make a new certificate: every session ends, and the browser asks about it again.
        #[arg(long)]
        new_cert: bool,
    },
    /// Turn the web UI off: it stops listening and every session ends. Its tokens stay.
    Off,
    /// List the tokens that log in to the web UI by label, make one, or revoke one.
    #[command(args_conflicts_with_subcommands = true)]
    Token {
        #[command(subcommand)]
        cmd: Option<UiTokenCmd>,
    },
}

#[derive(Debug, Subcommand)]
pub enum UiTokenCmd {
    /// Make a token and show it once.
    Add {
        /// Its label, 1 to 32 of a-z, 0-9 and -.
        label: String,
    },
    /// Revoke a token; the sessions it opened end at once.
    Rm {
        /// The token's label.
        label: String,
    },
}

/// Whether `c` only reads.
pub fn only_reads(c: &Option<UiCmd>) -> bool {
    matches!(c, None | Some(UiCmd::Token { cmd: None }))
}

/// Whether the web UI may run `c` itself (crate::owner::VIA_ENV): what reads,
/// and revoking a token, which only narrows who gets in.
pub fn allowed_from_the_web(c: &Option<UiCmd>) -> bool {
    only_reads(c)
        || matches!(
            c,
            Some(UiCmd::Token {
                cmd: Some(UiTokenCmd::Rm { .. })
            })
        )
}

pub(super) async fn ui_cmd(
    paths: &NodePaths,
    c: Option<UiCmd>,
    out: &mut dyn Write,
) -> Result<(), String> {
    if cfg!(windows) {
        return Err(NO_WEB_UI_HERE.into());
    }
    if crate::owner::via_web() && !allowed_from_the_web(&c) {
        return Err(crate::owner::NOT_FROM_THE_WEB.into());
    }
    let w = |out: &mut dyn Write, s: String| {
        let _ = writeln!(out, "{s}");
    };
    let Some(c) = c else {
        let (cfg, _) = read_config(paths).await?;
        let live = live_ui(paths).await?;
        let print = current_fingerprint(paths, &cfg);
        // `--json` keeps its lines; people get the page.
        match json::active() {
            true => {
                for line in status_lines(&cfg, live.as_ref(), print.as_deref()) {
                    w(out, line);
                }
            }
            false => show(out, &status_page(&cfg, live.as_ref(), print.as_deref())),
        }
        let mut data = status_data(&cfg, live.as_ref());
        data["fingerprint"] = json!(print);
        json::also("ui", data);
        return Ok(());
    };
    match c {
        UiCmd::On {
            listen,
            names,
            new_cert,
        } => {
            let at = listen.unwrap_or_else(|| UI_ADDRESS.to_string());
            let addr: std::net::SocketAddr = at.parse().map_err(|_| {
                format!("ui.listen {at:?}: an address and a port, like {UI_ADDRESS}")
            })?;
            let tls = !addr.ip().is_loopback();
            if !tls && (new_cert || !names.is_empty()) {
                return Err(format!(
                    "{at} is loopback, which the web UI serves without TLS: --host and --new-cert are for an address beyond it"
                ));
            }
            let live = live_ui(paths).await?;
            if !served_here(paths, live.as_ref()) {
                return Err(only_installed());
            }
            let (now, _) = read_config(paths).await?;
            let cert = if tls {
                Some(ui_cert(paths, &now, addr, &names, new_cert)?)
            } else {
                None
            };
            let first = now.ui.tokens.is_empty().then(new_token);
            edit(paths, |c| {
                c.ui.listen = Some(at.clone());
                if let Some(cert) = &cert {
                    c.ui.pin = Some(cert.pin.clone());
                }
                if let Some((_, t)) = &first
                    && c.ui.tokens.is_empty()
                {
                    c.ui.tokens.push(t.clone());
                }
                Ok(())
            })
            .await?;
            let scheme = if tls { "https" } else { "http" };
            w(out, format!("web UI on at {scheme}://{}", shown_at(addr)));
            if let Some(cert) = &cert {
                w(
                    out,
                    format!(
                        "its TLS certificate{} has the SHA-256 fingerprint\n  {}\ncompare it with the one your browser shows before you sign in",
                        if cert.made { ", made now," } else { "" },
                        cert.fingerprint
                    ),
                );
                if cert.made && now.ui.pin.is_some() {
                    w(out, "every session of the old certificate ends".into());
                }
                w(
                    out,
                    format!(
                        "the web UI can now be reached from the network; to keep it on this machine, run `nerve-node ui on` (loopback) and reach it with `ssh -L 7470:{UI_ADDRESS} <you>@<this machine>`"
                    ),
                );
                json::also(
                    "certificate",
                    json!({"fingerprint": cert.fingerprint, "made": cert.made}),
                );
            }
            if let Some((token, t)) = &first {
                w(
                    out,
                    format!(
                        "token {}: {token}\nit is shown only now; it logs in to the web UI (`nerve-node ui token add <label>` makes more)",
                        t.label
                    ),
                );
                json::also("token", json!({"label": t.label, "token": token}));
            }
            if let Some(state) = wait_for_listener(paths, &at).await {
                w(out, state);
            }
            Ok(())
        }
        UiCmd::Off => {
            edit(paths, |c| {
                c.ui.listen = None;
                Ok(())
            })
            .await?;
            w(out, "web UI off".into());
            if daemon_answers(paths).await {
                w(
                    out,
                    "it stops listening, and every session ends, now".into(),
                );
            }
            Ok(())
        }
        UiCmd::Token {
            cmd: Some(UiTokenCmd::Add { label }),
        } => {
            if !nerve_policy::config::valid_ui_label(&label) {
                return Err(format!(
                    "{label:?} is not a token label: 1 to 32 characters of a-z, 0-9 and -, not starting with -"
                ));
            }
            let (token, mut t) = new_token();
            t.label = label.clone();
            edit(paths, |c| {
                if c.ui.token(&label).is_some() {
                    return Err(format!(
                        "a token labelled {label} exists: `nerve-node ui token rm {label}` revokes it"
                    ));
                }
                c.ui.tokens.push(t.clone());
                Ok(())
            })
            .await?;
            w(
                out,
                format!("token {label}: {token}\nit is shown only now; it logs in to the web UI"),
            );
            json::also("token", json!({"label": label, "token": token}));
            Ok(())
        }
        UiCmd::Token { cmd: None } => {
            let (cfg, _) = read_config(paths).await?;
            if cfg.ui.tokens.is_empty() {
                w(
                    out,
                    "no token: `nerve-node ui token add <label>` makes one".into(),
                );
            }
            for t in &cfg.ui.tokens {
                w(out, format!("{} (made {})", t.label, made_text(&t.made)));
            }
            json::also("tokens", tokens_data(&cfg));
            Ok(())
        }
        UiCmd::Token {
            cmd: Some(UiTokenCmd::Rm { label }),
        } => {
            edit(paths, |c| {
                if c.ui.token(&label).is_none() {
                    return Err(format!("no web UI token is labelled {label}"));
                }
                c.ui.tokens.retain(|t| t.label != label);
                Ok(())
            })
            .await?;
            w(
                out,
                format!("token {label} revoked; the sessions it opened end"),
            );
            Ok(())
        }
    }
}

/// The web UI's TLS certificate as `ui on` leaves it.
struct Cert {
    pin: String,
    fingerprint: String,
    /// Whether it was made now.
    made: bool,
}

/// The web UI's certificate for `addr`: the one it has, or a new one when it
/// has none, its key is gone or is not the one `ui.pin` names, or `new` is
/// asked. It names `addr` when that is a specific address, this machine's
/// host name, each of `names`, and `localhost`. The key goes where the node
/// keeps its keys (`machine.secret_storage`), before the config names its
/// pin, as the relay's.
fn ui_cert(
    paths: &NodePaths,
    cfg: &NodeConfig,
    addr: std::net::SocketAddr,
    names: &[String],
    new: bool,
) -> Result<Cert, String> {
    let storage = cfg.machine.secret_storage;
    if !new
        && names.is_empty()
        && let Some(pin) = &cfg.ui.pin
        && let Ok(Some(id)) = crate::secrets::ui_tls(paths, storage)
        && id.pin() == *pin
    {
        return Ok(Cert {
            pin: pin.clone(),
            fingerprint: fingerprint(&id.cert_der),
            made: false,
        });
    }
    let mut all: Vec<String> = Vec::new();
    if !addr.ip().is_unspecified() {
        all.push(addr.ip().to_string());
    }
    all.push(crate::descriptor::host_name());
    for n in names {
        if n.is_empty() || n.contains(|c: char| c.is_whitespace() || c == '/') {
            return Err(format!("--host {n:?} is not a host name"));
        }
        all.push(n.clone());
    }
    all.dedup();
    let id = nerve_transport::tls::ServerIdentity::generate(&all)?;
    crate::secrets::store_ui_tls(paths, storage, &id)?;
    Ok(Cert {
        pin: id.pin(),
        fingerprint: fingerprint(&id.cert_der),
        made: true,
    })
}

/// A certificate's SHA-256 fingerprint as browsers show it: pairs of hex
/// digits, in capitals, between colons.
pub fn fingerprint(cert_der: &[u8]) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, cert_der);
    d.as_ref()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// How a URL names `addr`: an address that listens on every interface is
/// reached at this machine's name.
fn shown_at(addr: std::net::SocketAddr) -> String {
    if addr.ip().is_unspecified() {
        format!("{}:{}", crate::descriptor::host_name(), addr.port())
    } else {
        addr.to_string()
    }
}

/// A new token and what node.toml keeps of it (the label is the caller's):
/// 43 characters of `a-z0-9`, over 220 bits, as the relay's.
fn new_token() -> (String, nerve_policy::config::UiToken) {
    let (token, hash) = crate::relay::new_token();
    let t = nerve_policy::config::UiToken {
        label: FIRST_TOKEN.into(),
        token_sha256: hash,
        made: utc_text(crate::now_ms()),
    };
    (token, t)
}

/// When a token was made, as `ui token` says it.
fn made_text(made: &str) -> &str {
    if made.is_empty() {
        "at a time not kept"
    } else {
        made
    }
}

/// The web UI's state as the running node tells it (`status`): `None` when
/// no node runs.
async fn live_ui(paths: &NodePaths) -> Result<Option<Value>, String> {
    #[cfg(unix)]
    match nerve_transport::ctl::call(&paths.ctl_socket(), "status", json!({})).await {
        Ok(v) => Ok(Some(v["ui"].clone())),
        Err(e) if e == nerve_transport::ctl::NOT_RUNNING => Ok(None),
        Err(e) => Err(e),
    }
    #[cfg(not(unix))]
    {
        let _ = paths;
        Ok(None)
    }
}

/// Whether the node at `paths` serves the web UI: the running node says
/// so; else it is the installed node, which serves it once it runs.
fn served_here(paths: &NodePaths, live: Option<&Value>) -> bool {
    match live {
        Some(v) => v["served"] == true,
        None => crate::service::is_service_node(paths),
    }
}

/// What the running node did with the address, once it tried: listening,
/// or why it cannot. Waits up to 3 seconds; `None` when no node runs or it
/// did not tell in time.
async fn wait_for_listener(paths: &NodePaths, at: &str) -> Option<String> {
    for _ in 0..30 {
        let live = live_ui(paths).await.ok()??;
        let state = live["status"].as_str().unwrap_or_default();
        if live["listen"].as_str() == Some(at)
            && (state.starts_with("listening") || state.starts_with("cannot"))
        {
            return Some(format!("the node: {state}"));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

/// What a bare `ui` shows people: whether the web UI is on and where, the
/// node's word on it, its certificate and its tokens.
fn status_page(cfg: &NodeConfig, live: Option<&Value>, print: Option<&str>) -> Page {
    let url = |at: &str| match at.parse::<std::net::SocketAddr>() {
        Ok(a) if !a.ip().is_loopback() => format!("https://{}", shown_at(a)),
        _ => format!("http://{at}"),
    };
    let mut p = match &cfg.ui.listen {
        None => page("web UI off"),
        Some(_) => page("web UI on"),
    };
    match (&cfg.ui.listen, live) {
        (None, _) => {
            p.next("Turn it on", "nerve-node ui on");
        }
        (Some(at), Some(v)) => {
            p.row("Address", url(at));
            p.row("State", v["status"].as_str().unwrap_or("not known"));
        }
        (Some(at), None) => {
            p.row("Address", url(at));
            p.row("State", "once the node runs");
        }
    }
    if let Some(f) = print {
        p.row("Certificate", format!("SHA-256 {f}"));
    }
    if live.is_some_and(|v| v["served"] == false) {
        p.note(only_installed());
    }
    if cfg.ui.tokens.is_empty() {
        p.row("Tokens", "none");
        p.next("Make one", "nerve-node ui token add <label>");
    } else {
        let labels: Vec<&str> = cfg.ui.tokens.iter().map(|t| t.label.as_str()).collect();
        p.row("Tokens", labels.join(", "));
    }
    p
}

/// The lines of a bare `ui` for `--json`, which gives them as they were.
fn status_lines(cfg: &NodeConfig, live: Option<&Value>, print: Option<&str>) -> Vec<String> {
    let mut lines = Vec::new();
    let url = |at: &str| match at.parse::<std::net::SocketAddr>() {
        Ok(a) if !a.ip().is_loopback() => format!("https://{}", shown_at(a)),
        _ => format!("http://{at}"),
    };
    match (&cfg.ui.listen, live) {
        (None, _) => lines.push("web UI off".into()),
        (Some(at), Some(v)) => {
            lines.push(format!("web UI on at {}", url(at)));
            lines.push(format!(
                "the node: {}",
                v["status"].as_str().unwrap_or("not known")
            ));
        }
        (Some(at), None) => lines.push(format!("web UI on at {}, once the node runs", url(at))),
    }
    if let Some(f) = print {
        lines.push(format!("its TLS certificate's SHA-256 fingerprint: {f}"));
    }
    if live.is_some_and(|v| v["served"] == false) {
        lines.push(only_installed());
    }
    if cfg.ui.tokens.is_empty() {
        lines.push("no token: `nerve-node ui token add <label>` makes one".into());
    } else {
        let labels: Vec<&str> = cfg.ui.tokens.iter().map(|t| t.label.as_str()).collect();
        lines.push(format!("tokens: {}", labels.join(", ")));
    }
    lines
}

/// The fingerprint of the certificate the web UI serves beyond loopback, if
/// it has one there.
fn current_fingerprint(paths: &NodePaths, cfg: &NodeConfig) -> Option<String> {
    let at: std::net::SocketAddr = cfg.ui.listen.as_deref()?.parse().ok()?;
    if at.ip().is_loopback() {
        return None;
    }
    let id = crate::secrets::ui_tls(paths, cfg.machine.secret_storage).ok()??;
    (cfg.ui.pin.as_deref() == Some(id.pin().as_str())).then(|| fingerprint(&id.cert_der))
}

fn status_data(cfg: &NodeConfig, live: Option<&Value>) -> Value {
    json!({
        "listen": cfg.ui.listen,
        "status": live.map(|v| v["status"].clone()),
        "served": live.map(|v| v["served"].clone()),
        "tokens": tokens_data(cfg),
    })
}

fn tokens_data(cfg: &NodeConfig) -> Value {
    cfg.ui
        .tokens
        .iter()
        .map(|t| json!({"label": t.label, "made": t.made}))
        .collect()
}

/// `ms` since the epoch as RFC 3339 in UTC, to the second.
pub fn utc_text(ms: u64) -> String {
    let secs = ms / 1000;
    let (days, rest) = (secs / 86_400, secs % 86_400);
    // Days to a civil date (Howard Hinnant's algorithm), for any day after
    // 1970.
    let z = days as i64 + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fingerprint_is_written_as_browsers_show_it() {
        let f = fingerprint(b"abc");
        assert_eq!(
            f,
            "BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD"
        );
    }

    #[test]
    fn a_time_is_rfc3339_in_utc() {
        assert_eq!(utc_text(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_text(1_793_620_800_000), "2026-11-02T12:00:00Z");
        assert_eq!(utc_text(951_782_399_000), "2000-02-28T23:59:59Z");
        assert_eq!(utc_text(951_868_800_000), "2000-03-01T00:00:00Z");
    }

    #[test]
    fn the_web_ui_may_read_and_revoke_and_nothing_more() {
        use clap::Parser;
        let parse = |args: &[&str]| match Cli::try_parse_from(
            std::iter::once("nerve-node").chain(args.iter().copied()),
        )
        .unwrap()
        .cmd
        {
            Cmd::Ui { cmd } => cmd,
            other => panic!("{other:?}"),
        };
        for ok in [
            &["ui"][..],
            &["ui"],
            &["ui", "token"],
            &["ui", "token", "rm", "laptop"],
        ] {
            assert!(allowed_from_the_web(&parse(ok)), "{ok:?}");
        }
        for no in [
            &["ui", "on"][..],
            &["ui", "on", "--listen", "0.0.0.0:7470", "--new-cert"],
            &["ui", "on", "--listen", "127.0.0.1:1"],
            &["ui", "off"],
            &["ui", "token", "add", "x"],
        ] {
            assert!(!allowed_from_the_web(&parse(no)), "{no:?}");
        }
    }
}
