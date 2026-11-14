//! The owner's commands in the terminal that the web UI has too: `pair`,
//! `nodes` and `token` ask the running center over its attach socket or
//! pipe (crate::attach), whose handlers are the web UI's; `log` reads the
//! center's log file, so it works with the center stopped too. The output
//! is in the style of both programs (nerve_service::out).

use std::io::Write;
use std::path::Path;

use serde_json::{Value, json};

use nerve_policy::rules::visible;
use nerve_service::out::{Page, Style, Tone};

use crate::config::{NodesCmd, TokenCmd};

/// Runs `pair`, `nodes` or `token` against the center in `state`, and
/// shows what it did on `out`.
pub async fn run(
    state: &Path,
    cmd: &crate::config::Cmd,
    installed: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    use crate::config::Cmd;
    let command = commands(state, installed);
    let page = match cmd {
        Cmd::Pair => pair_page(&call(state, installed, "POST", "/api/pair", json!({})).await?),
        Cmd::Nodes { cmd } => nodes(state, installed, cmd.as_ref(), &command, out).await?,
        Cmd::Token(t) => token(state, installed, t, &command, out).await?,
        _ => return Err("only pair, nodes and token ask the running center".into()),
    };
    let _ = out.write_all(page.render(Style::stdout()).as_bytes());
    Ok(())
}

/// The owner's commands for the center in `state`, as a person types them
/// where they are: for the installed center with `sudo` (on Windows in an
/// administrator's terminal), for one a harness or a person started with
/// the folder it needs, as `status` names them.
fn commands(state: &Path, installed: bool) -> impl Fn(&str) -> String {
    let state = state.to_path_buf();
    let system = crate::service::Layout::system();
    let installed_dir = match installed {
        true => Some(state.clone()),
        false => system.installed().then(|| system.state.clone()),
    };
    move |what: &str| {
        crate::ui::command_of(
            what,
            &state,
            installed_dir.as_deref(),
            &crate::config::default_state_dir(),
            true,
            cfg!(windows),
        )
    }
}

/// One request to the running center in `state`, as the web UI would send
/// it; its answer. A center that does not run is said plainly, with the
/// command that starts the installed one (`installed`).
pub async fn call(
    state: &Path,
    installed: bool,
    method: &str,
    path: &str,
    body: Value,
) -> Result<Value, String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    if crate::owner::not_yours(state) {
        return Err(only_the_owner("ask the installed center"));
    }
    let not_running = || match installed {
        true => format!(
            "the center does not run; {} starts it",
            crate::service::admin_command("service start")
        ),
        false => format!("no center runs in {}", state.display()),
    };
    if crate::attach::runs(state) == Some(false) {
        return Err(not_running());
    }
    let stream = open(state, installed)
        .await
        .map_err(|e| match crate::attach::runs(state) {
            Some(true) => e,
            _ => not_running(),
        })?;
    let (r, mut w) = tokio::io::split(stream);
    let request = json!({"method": method, "path": path, "body": body});
    w.write_all(format!("{}\n{request}\n", crate::attach::OWNER_HELLO).as_bytes())
        .await
        .map_err(|e| format!("cannot ask the center: {e}"))?;
    let mut line = String::new();
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::io::BufReader::new(r).read_line(&mut line),
    )
    .await;
    match read {
        Ok(Ok(n)) if n > 0 => {}
        Ok(Ok(_)) => return Err("the center ended the connection without an answer".into()),
        Ok(Err(e)) => return Err(format!("cannot read the center's answer: {e}")),
        Err(_) => return Err("the center did not answer within 30 seconds".into()),
    }
    let v: Value = serde_json::from_str(&line).map_err(|e| format!("the center's answer: {e}"))?;
    match v.get("ok") {
        Some(ok) => Ok(ok.clone()),
        None => Err(v["error"]
            .as_str()
            .unwrap_or("the center refused it")
            .to_string()),
    }
}

/// Why another account's command cannot `what` ("ask the installed
/// center"), and how it can.
fn only_the_owner(what: &str) -> String {
    match cfg!(windows) {
        true => format!("only an administrator may {what}: run it in an administrator's terminal"),
        false => format!("only root and the center's account {what}: run it with sudo"),
    }
}

/// The connection to the center in `state`: its attach socket.
#[cfg(unix)]
async fn open(state: &Path, _installed: bool) -> Result<tokio::net::UnixStream, String> {
    let path = crate::attach::socket_path(state);
    tokio::net::UnixStream::connect(&path)
        .await
        .map_err(|e| format!("the center does not answer on {}: {e}", path.display()))
}

/// Whether a pipe that neither SYSTEM nor the administrators own, but the
/// account `who`, may answer: the installed center's is the service's (an
/// administrator's own account is shared by their unelevated programs, and
/// a program could make the pipe while the service is stopped); one run by
/// hand in a folder of its own runs as the caller (`own`).
#[cfg_attr(not(windows), allow(dead_code))]
fn foreign_pipe_may_answer(who: &str, own: &str, service: &str, installed: bool) -> bool {
    who == if installed { service } else { own }
}

/// The connection to the center in `state`: its attach pipe, once it proved
/// to be the center's (the installed service's, or for one run by hand this
/// account's), as one another account made first learns nothing.
#[cfg(windows)]
async fn open(
    state: &Path,
    installed: bool,
) -> Result<tokio::net::windows::named_pipe::NamedPipeClient, String> {
    use nerve_service::win::pipe::{PIPE_BUSY, foreign_owner, open_identified};
    use nerve_service::win::process::user_of;
    use nerve_service::win::sid::sid_text;
    use std::os::windows::io::AsRawHandle;
    let name = crate::attach::pipe_name(state);
    let mut busy = 0;
    let client = loop {
        match open_identified(&name) {
            Ok(c) => break c,
            Err(e) if e.raw_os_error() == Some(PIPE_BUSY) && busy < 50 => {
                busy += 1;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(e) => return Err(format!("the center does not answer on {name}: {e}")),
        }
    };
    let foreign = foreign_owner(client.as_raw_handle(), None)
        .map_err(|e| format!("cannot check the pipe {name}: {e}"))?;
    if let Some(owner) = foreign {
        let who = sid_text(&owner).unwrap_or_else(|e| e);
        let own = user_of(None)
            .map_err(|e| e.to_string())
            .and_then(|u| sid_text(&u))?;
        if !foreign_pipe_may_answer(&who, &own, &crate::winsvc::account_sid(), installed) {
            return Err(format!(
                "the pipe {name} belongs to {who}, not to the center, so nothing was sent to it"
            ));
        }
    }
    Ok(client)
}

/// What `pair` shows: the link and when it runs out.
fn pair_page(v: &Value) -> Page {
    let mut p = crate::service::page().state("pairing link", Tone::Plain);
    p.row("Link", v["link"].as_str().unwrap_or_default());
    if let Some(ms) = v["expires_ms"].as_u64() {
        let left = ms.saturating_sub(crate::util::now_ms());
        p.row(
            "Runs out",
            format!(
                "in {} ({} UTC)",
                nerve_transport::log::span(std::time::Duration::from_millis(left)),
                nerve_service::out::time(ms)
            ),
        );
    }
    p.next("On a Linux machine", "nerve-node center add -");
    p.note("Paste the link on the line under the command, or in the Nerve app. On Windows, open the link.");
    p
}

/// The paired machines of `overview`, a row each: name, state, system and
/// version.
fn node_rows(overview: &Value) -> Vec<Vec<String>> {
    overview["nodes"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|n| {
            let state = match (n["disabled"] == true, n["online"] == true) {
                (true, _) => "off",
                (false, true) => "online",
                (false, false) => "offline",
            };
            vec![
                n["name"].as_str().unwrap_or_default().to_string(),
                state.to_string(),
                format!(
                    "{} {}",
                    n["platform"].as_str().unwrap_or_default(),
                    n["arch"].as_str().unwrap_or_default()
                ),
                n["software"].as_str().unwrap_or("-").to_string(),
            ]
        })
        .collect()
}

/// What `nodes` shows: the paired machines.
fn nodes_page(overview: &Value, command: &dyn Fn(&str) -> String) -> Page {
    let rows = node_rows(overview);
    let mut p = crate::service::page().state(
        match rows.len() {
            0 => "no machine paired".to_string(),
            1 => "1 machine".to_string(),
            n => format!("{n} machines"),
        },
        Tone::Plain,
    );
    if rows.is_empty() {
        p.next("Pair one", command("pair"));
    }
    p.list(None, rows);
    p
}

/// The id of the paired machine `name` in `overview`. A name two machines
/// share is refused: the web UI tells them apart.
fn node_id(overview: &Value, name: &str) -> Result<String, String> {
    let found: Vec<&Value> = overview["nodes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|n| n["name"] == name)
        .collect();
    match found[..] {
        [n] => Ok(n["id"].as_str().unwrap_or_default().to_string()),
        [] => Err(format!("no machine named {name} is paired")),
        _ => Err(format!(
            "{} machines are named {name}: rename one in the web UI first",
            found.len()
        )),
    }
}

/// `nodes` and its changes: the change, said as a line, then the machines.
async fn nodes(
    state: &Path,
    installed: bool,
    cmd: Option<&NodesCmd>,
    command: &dyn Fn(&str) -> String,
    out: &mut dyn Write,
) -> Result<Page, String> {
    let overview = || call(state, installed, "GET", "/api/overview", json!({}));
    let Some((name, path, body, done)) = cmd.and_then(node_change) else {
        return Ok(nodes_page(&overview().await?, command));
    };
    let id = node_id(&overview().await?, name)?;
    let mut body = body;
    body["id"] = json!(id);
    call(state, installed, "POST", path, body).await?;
    let _ = writeln!(out, "{done} {name}\n");
    Ok(nodes_page(&overview().await?, command))
}

/// The web UI's request that `cmd` makes of the machine it names: the
/// name, the path, the body without the machine's id, and what to say
/// when it is done. None for `nodes list`, which changes nothing.
fn node_change(cmd: &NodesCmd) -> Option<(&str, &'static str, Value, &'static str)> {
    Some(match cmd {
        NodesCmd::List => return None,
        NodesCmd::Disable { name } => (
            name,
            "/api/nodes/disable",
            json!({"disabled": true}),
            "turned off",
        ),
        NodesCmd::Enable { name } => (
            name,
            "/api/nodes/disable",
            json!({"disabled": false}),
            "turned on",
        ),
        NodesCmd::Rm { name } => (name, "/api/nodes/remove", json!({}), "removed"),
    })
}

/// `token new|list|rm`.
async fn token(
    state: &Path,
    installed: bool,
    cmd: &TokenCmd,
    command: &dyn Fn(&str) -> String,
    out: &mut dyn Write,
) -> Result<Page, String> {
    let list = || call(state, installed, "GET", "/api/tokens", json!({}));
    match cmd {
        TokenCmd::New { label } => {
            let label = label.clone().unwrap_or_default();
            let made = call(
                state,
                installed,
                "POST",
                "/api/tokens/create",
                json!({"label": label}),
            )
            .await?;
            let overview = call(state, installed, "GET", "/api/overview", json!({})).await?;
            // The label the center kept (it cuts a long one), which `token
            // rm` finds the token by.
            let kept = list().await?;
            let label = kept
                .as_array()
                .into_iter()
                .flatten()
                .find(|t| t["id"] == made["id"])
                .and_then(|t| t["label"].as_str())
                .unwrap_or(&label);
            Ok(new_token_page(
                &made,
                label,
                &overview["mcp"],
                installed,
                command,
            ))
        }
        TokenCmd::List => Ok(tokens_page(&list().await?, command)),
        TokenCmd::Rm { label } => {
            let tokens = list().await?;
            let id = token_id(&tokens, label)?;
            call(
                state,
                installed,
                "POST",
                "/api/tokens/delete",
                json!({"id": id}),
            )
            .await?;
            let _ = writeln!(out, "removed the harness token {label}\n");
            Ok(tokens_page(&list().await?, command))
        }
    }
}

/// What `token new` shows: the token, once, with what a harness needs, as
/// the web UI's Connect a harness card shows it; `mcp` is how the center
/// serves MCP. `label` is the one the center kept; `installed` says it is
/// the installed center, whose settings `set` changes.
fn new_token_page(
    made: &Value,
    label: &str,
    mcp: &Value,
    installed: bool,
    command: &dyn Fn(&str) -> String,
) -> Page {
    let token = made["token"].as_str().unwrap_or_default();
    let mut p = crate::service::page().state("new harness token", Tone::Good);
    p.row("Token", token);
    p.row(
        "Label",
        match label.trim() {
            "" => "harness",
            l => l,
        },
    );
    let header = format!("Authorization: Bearer {token}");
    let mut shown_once = String::new();
    match mcp["url"].as_str() {
        Some(url) if mcp["mode"] == "http" => {
            p.row("URL", url).row("Header", header.clone());
            p.next(
                "Claude Code",
                format!("claude mcp add --transport http nerve {url} --header \"{header}\""),
            );
            if let Some(f) = mcp["fingerprint"].as_str() {
                p.note(format!(
                    "Beyond loopback the endpoint uses TLS with the center's own certificate: let the harness trust it by its pin {f}."
                ));
            }
            // Only where the page shows that line.
            shown_once.push_str(" The Claude Code line puts it in your shell's history.");
        }
        // `set` changes the installed center's settings, not another's.
        _ if installed => {
            p.next("Turn on MCP over HTTP", command("set mcp http"));
        }
        _ => {
            p.note("MCP over HTTP is off in this center: start it with --mcp http.");
        }
    }
    p.note(format!(
        "It is shown only now; the center keeps its hash.{shown_once}"
    ));
    p
}

/// What `token list` shows: each harness token by its label.
fn tokens_page(tokens: &Value, command: &dyn Fn(&str) -> String) -> Page {
    let rows: Vec<Vec<String>> = tokens
        .as_array()
        .into_iter()
        .flatten()
        .map(|t| {
            let made = match t["created_ms"].as_u64() {
                Some(ms) => format!("made {} UTC", nerve_service::out::time(ms)),
                None => "from the settings".to_string(),
            };
            vec![
                t["label"].as_str().unwrap_or_default().to_string(),
                made,
                t["id"].as_str().unwrap_or_default().to_string(),
            ]
        })
        .collect();
    let mut p = crate::service::page().state(
        match rows.len() {
            0 => "no harness token".to_string(),
            1 => "1 harness token".to_string(),
            n => format!("{n} harness tokens"),
        },
        Tone::Plain,
    );
    if rows.is_empty() {
        p.next("Make one", command("token new"));
    }
    p.list(None, rows);
    p
}

/// The id of the harness token `label` (its label or its id) in `tokens`.
/// The one of the settings file is not the center's to remove, and a label
/// two tokens share is refused.
fn token_id(tokens: &Value, label: &str) -> Result<String, String> {
    let all: Vec<&Value> = tokens.as_array().into_iter().flatten().collect();
    if all.iter().any(|t| t["id"] == label && t["id"] != "") {
        return Ok(label.to_string());
    }
    let found: Vec<&&Value> = all.iter().filter(|t| t["label"] == label).collect();
    match found[..] {
        [t] if t["settings"] == true => Err(format!(
            "{label} is set in the center's settings, not made by it: remove it there"
        )),
        [t] => Ok(t["id"].as_str().unwrap_or_default().to_string()),
        [] => Err(format!("no harness token is labelled {label}")),
        _ => Err(format!(
            "{} harness tokens are labelled {label}: name one by its id (`token list` shows it)",
            found.len()
        )),
    }
}

/// `log`: the center's log file in `state`, the older file first; with
/// `problems` errors and warnings only, with `last` the newest N of them,
/// and with `follow` the new lines as they come.
pub async fn log(
    state: &Path,
    follow: bool,
    last: Option<usize>,
    problems: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    let file = nerve_transport::log::file_in(state);
    // A plain file only, as everything else in the center's folder is read:
    // the service's account owns the folder on Windows, where an
    // administrator reads it, and may put a link or a pipe there.
    let read = |p: &Path| match nerve_transport::files::read_plain(p) {
        Ok(b) => Ok(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(only_the_owner("read the installed center's log"))
        }
        Err(e) => Err(format!("{}: {e}", p.display())),
    };
    let mut older = file.clone().into_os_string();
    older.push(".1");
    let mut bytes = read(Path::new(&older))?;
    let current = read(&file)?;
    let mut at = current.len();
    // The file's first bytes tell it from the one that replaces it, which
    // can be as long already.
    let head = |b: &[u8]| b[..b.len().min(64)].to_vec();
    let mut first = head(&current);
    // A line the center is still writing waits for its end.
    let whole = current
        .iter()
        .rposition(|b| *b == b'\n')
        .map_or(0, |i| i + 1);
    bytes.extend_from_slice(&current[..whole]);
    let mut rest: Vec<u8> = current[whole..].to_vec();
    let mut lines = log_lines(&bytes, problems);
    if let Some(n) = last {
        lines.drain(..lines.len().saturating_sub(n));
    }
    for l in &lines {
        let _ = writeln!(out, "{l}");
    }
    let _ = out.flush();
    if !follow {
        return Ok(());
    }
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let now = read(&file)?;
        if now.len() < at || !now.starts_with(&first) {
            // Moved aside: what the old file got after the last look, then
            // the new file from its start. Its head is the new file's now,
            // not the old one's: a stale one would show the move again at
            // every look.
            let moved = read(Path::new(&older))?;
            rest.extend_from_slice(moved.get(at..).unwrap_or_default());
            at = 0;
            first.clear();
        }
        if first.len() < 64 {
            first = head(&now);
        }
        rest.extend_from_slice(&now[at..]);
        at = now.len();
        let Some(end) = rest.iter().rposition(|b| *b == b'\n') else {
            continue;
        };
        let done: Vec<u8> = rest.drain(..=end).collect();
        for l in log_lines(&done, problems) {
            // The reader is gone (`| head -1`): nobody wants more.
            if writeln!(out, "{l}").is_err() {
                return Ok(());
            }
        }
        if out.flush().is_err() {
            return Ok(());
        }
    }
}

/// The lines of the log `bytes` (JSON a line) as people read them: the
/// time, the level and the message, with the machine it is about.
fn log_lines(bytes: &[u8], problems: bool) -> Vec<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| !problems || matches!(v["level"].as_str(), Some("error" | "warn")))
        .map(|v| {
            let mut line = format!(
                "{}  {}  {}",
                nerve_service::out::time(v["ts"].as_u64().unwrap_or_default()),
                visible(v["level"].as_str().unwrap_or_default()),
                visible(v["msg"].as_str().unwrap_or_default())
            );
            if let Some(n) = v["node"].as_str() {
                line.push_str(&format!(" ({})", visible(n)));
            }
            line
        })
        .collect()
}

#[cfg(test)]
mod tests {
    /// The installed center's pipe is the service's, never the caller's own
    /// account (an administrator's unelevated programs run as it); a center
    /// run by hand answers as the caller (round 4, security 1).
    #[test]
    fn the_installed_centers_pipe_is_not_the_callers_own() {
        let (own, service) = ("S-1-5-21-1-2-3-1001", "S-1-5-80-9");
        assert!(!super::foreign_pipe_may_answer(own, own, service, true));
        assert!(super::foreign_pipe_may_answer(service, own, service, true));
        assert!(super::foreign_pipe_may_answer(own, own, service, false));
        assert!(!super::foreign_pipe_may_answer(
            "S-1-5-21-1-2-3-1002",
            own,
            service,
            false
        ));
    }

    use super::*;

    /// The commands of the installed center.
    fn admin(what: &str) -> String {
        format!("sudo nerve-center {what}")
    }

    /// The commands of a center that was started by hand in another
    /// folder name that folder and use no `sudo`; the installed one's
    /// (`commands`) are as `status` gives them.
    #[test]
    fn the_pages_name_the_commands_of_the_center_they_ask() {
        let by_hand = |what: &str| format!("nerve-center {what} --state-dir /srv/c");
        let none = nodes_page(&json!({"nodes": []}), &by_hand).render(Style::PLAIN);
        assert!(
            none.contains("Pair one:  nerve-center pair --state-dir /srv/c\n"),
            "{none}"
        );
        let none = tokens_page(&json!([]), &by_hand).render(Style::PLAIN);
        assert!(
            none.contains("Make one:  nerve-center token new --state-dir /srv/c\n"),
            "{none}"
        );
        let state = Path::new("/srv/c");
        assert_eq!(
            commands(state, true)("pair"),
            match cfg!(windows) {
                true => "nerve-center pair",
                false => "sudo nerve-center pair",
            }
        );
    }

    /// The paired machines as a list, a machine that is off said so; a
    /// name is looked up once, a shared one refused.
    #[test]
    fn nodes_are_listed_and_found_by_name() {
        let overview = json!({"nodes": [
            {"id": "n1", "name": "lab", "online": true, "disabled": false, "platform": "linux", "arch": "x86_64", "software": "0.1.0"},
            {"id": "n2", "name": "desk", "online": false, "disabled": true, "platform": "windows", "arch": "x86_64"},
        ]});
        let page = nodes_page(&overview, &admin).render(Style::PLAIN);
        assert!(page.contains(" · 2 machines\n"), "{page}");
        assert!(
            page.contains(
                "\n  lab    online   linux x86_64     0.1.0\n  desk   off      windows x86_64   -\n"
            ),
            "{page}"
        );
        assert_eq!(node_id(&overview, "desk").unwrap(), "n2");
        assert!(
            node_id(&overview, "nope")
                .unwrap_err()
                .contains("no machine named nope")
        );
        let twice = json!({"nodes": [{"id": "a", "name": "x"}, {"id": "b", "name": "x"}]});
        assert!(
            node_id(&twice, "x")
                .unwrap_err()
                .contains("2 machines are named x")
        );
        let none = nodes_page(&json!({"nodes": []}), &admin).render(Style::PLAIN);
        assert!(none.contains(" · no machine paired\n"), "{none}");
        assert!(none.contains("Next  Pair one:  "), "{none}");
    }

    /// A token is found by its label or its id; the settings file's is not
    /// the center's to remove.
    #[test]
    fn a_token_is_found_by_label_or_id() {
        let tokens = json!([
            {"id": "", "label": "NERVE_CENTER_HARNESS_TOKEN", "settings": true},
            {"id": "t1", "label": "laptop", "created_ms": 0},
            {"id": "t2", "label": "ci", "created_ms": 0},
            {"id": "t3", "label": "ci", "created_ms": 0},
        ]);
        assert_eq!(token_id(&tokens, "laptop").unwrap(), "t1");
        assert_eq!(token_id(&tokens, "t3").unwrap(), "t3");
        assert!(token_id(&tokens, "ci").unwrap_err().contains("by its id"));
        assert!(
            token_id(&tokens, "NERVE_CENTER_HARNESS_TOKEN")
                .unwrap_err()
                .contains("set in the center's settings")
        );
        let page = tokens_page(&tokens, &admin).render(Style::PLAIN);
        assert!(page.contains(" · 4 harness tokens\n"), "{page}");
        assert!(
            page.contains("  laptop                       made 1970-01-01 00:00:00 UTC   t1\n"),
            "{page}"
        );
    }

    /// A new token is shown once with what a harness needs, as the web
    /// UI's card shows it; with MCP over HTTP off, how to turn it on.
    #[test]
    fn a_new_token_comes_with_what_a_harness_needs() {
        let made = json!({"id": "t1", "token": "nrv_abc"});
        let mcp = json!({"mode": "http", "url": "http://127.0.0.1:7481/mcp"});
        let page = new_token_page(&made, "", &mcp, true, &admin).render(Style::PLAIN);
        assert!(page.contains("The Claude Code line puts it"), "{page}");
        for want in [
            "  Token       nrv_abc\n",
            "  Label       harness\n",
            "  URL         http://127.0.0.1:7481/mcp\n",
            "Next  Claude Code:  claude mcp add --transport http nerve http://127.0.0.1:7481/mcp --header \"Authorization: Bearer nrv_abc\"\n",
        ] {
            assert!(page.contains(want), "{want}\n{page}");
        }
        let off = json!({"mode": "off"});
        let page = new_token_page(&made, "ci", &off, true, &admin).render(Style::PLAIN);
        assert!(
            page.contains("Turn on MCP over HTTP:  sudo nerve-center set mcp http\n"),
            "{page}"
        );
        // A center that was started by hand has no `set`: its page says
        // the flag and names no command of the installed one.
        let by_hand = |what: &str| format!("nerve-center {what} --state-dir /srv/c");
        let page = new_token_page(&made, "ci", &off, false, &by_hand).render(Style::PLAIN);
        assert!(!page.contains("set mcp http"), "{page}");
        assert!(page.contains("--mcp http"), "{page}");
        // The shell history is named only where the page shows the line
        // that puts the token in it (round 3, correctness 3).
        assert!(!page.contains("Claude Code line"), "{page}");
        assert!(!page.contains("shell's history"), "{page}");
    }

    /// `nodes disable|enable|rm` send the web UI's requests for the
    /// machine; `nodes list` changes nothing.
    #[test]
    fn a_machine_is_turned_off_on_or_removed_as_the_web_ui_does() {
        let name = || "lab".to_string();
        let off = NodesCmd::Disable { name: name() };
        let (n, path, body, done) = node_change(&off).unwrap();
        assert_eq!((n, path, done), ("lab", "/api/nodes/disable", "turned off"));
        assert_eq!(body, json!({"disabled": true}));
        let on = NodesCmd::Enable { name: name() };
        let (_, path, body, done) = node_change(&on).unwrap();
        assert_eq!((path, done), ("/api/nodes/disable", "turned on"));
        assert_eq!(body, json!({"disabled": false}));
        let rm = NodesCmd::Rm { name: name() };
        let (_, path, _, done) = node_change(&rm).unwrap();
        assert_eq!((path, done), ("/api/nodes/remove", "removed"));
        assert!(node_change(&NodesCmd::List).is_none());
    }

    /// `log` reads the older file first, then the current one up to its
    /// last whole line; `--last` keeps the newest N, `--problems` the
    /// errors and warnings.
    #[tokio::test]
    async fn the_log_reads_both_files_and_keeps_the_newest() {
        let d = tempfile::tempdir().unwrap();
        let file = nerve_transport::log::file_in(d.path());
        let mut older = file.clone().into_os_string();
        older.push(".1");
        let line = |ts: u64, level: &str, msg: &str| {
            format!("{}\n", json!({"ts": ts * 1000, "level": level, "msg": msg}))
        };
        std::fs::write(&older, line(1, "info", "one") + &line(2, "error", "two")).unwrap();
        std::fs::write(
            &file,
            line(3, "warn", "three") + &line(4, "info", "four") + "{\"ts\":5000,\"lev",
        )
        .unwrap();
        let said = |last: Option<usize>, problems: bool| {
            let state = d.path().to_path_buf();
            async move {
                let mut out = Vec::new();
                log(&state, false, last, problems, &mut out).await.unwrap();
                String::from_utf8(out)
                    .unwrap()
                    .lines()
                    .map(|l| l.rsplit("  ").next().unwrap().to_string())
                    .collect::<Vec<_>>()
            }
        };
        assert_eq!(said(None, false).await, ["one", "two", "three", "four"]);
        assert_eq!(said(Some(2), false).await, ["three", "four"]);
        assert_eq!(said(None, true).await, ["two", "three"]);
        assert_eq!(said(Some(1), true).await, ["three"]);
    }

    /// Another account's `log` of the installed center is told to use
    /// sudo, not given the system's refusal (round 1 of #213's second
    /// pass, correctness 8).
    #[cfg(unix)]
    #[tokio::test]
    async fn a_log_this_account_may_not_read_says_how_to_read_it() {
        if nerve_transport::net::euid() == 0 {
            eprintln!("skipped: root reads every file");
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let file = nerve_transport::log::file_in(d.path());
        std::fs::write(&file, "").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();
        let e = log(d.path(), false, None, false, &mut Vec::new())
            .await
            .unwrap_err();
        assert!(e.contains("run it with sudo"), "{e}");
    }

    /// The log's lines read as the node's do: the time, the level, the
    /// message and its machine; `--problems` keeps errors and warnings.
    #[test]
    fn the_log_reads_as_the_nodes() {
        let bytes = b"{\"ts\":0,\"level\":\"info\",\"msg\":\"the center started\"}\n{\"ts\":1000,\"level\":\"warn\",\"node\":\"lab\",\"msg\":\"the link dropped\"}\nnot json\n";
        assert_eq!(
            log_lines(bytes, false),
            [
                "1970-01-01 00:00:00  info  the center started",
                "1970-01-01 00:00:01  warn  the link dropped (lab)"
            ]
        );
        assert_eq!(log_lines(bytes, true).len(), 1);
    }

    /// Output that a test reads while `log --follow` writes it.
    #[derive(Clone, Default)]
    struct Seen(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl Write for Seen {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Seen {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }

        async fn until(&self, what: &str) {
            for _ in 0..100 {
                if self.text().contains(what) {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            panic!("{what:?} was not shown: {}", self.text());
        }
    }

    /// `log --follow` shows what the old file got just before the center
    /// moved it aside, then the new file (round 2 of #213's second pass,
    /// correctness 3), once each: lines longer than the 64 bytes that tell
    /// the files apart, and a look after the move (round 3, correctness 1).
    #[tokio::test]
    async fn log_follow_shows_what_the_old_file_got_before_it_was_moved() {
        let d = tempfile::tempdir().unwrap();
        let file = nerve_transport::log::file_in(d.path());
        let mut older = file.clone().into_os_string();
        older.push(".1");
        let line = |ts: u64, msg: &str| {
            format!(
                "{}\n",
                json!({"ts": ts * 1000, "level": "info", "msg": msg})
            )
        };
        let append = |text: String| {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&file)
                .unwrap();
            f.write_all(text.as_bytes()).unwrap();
        };
        let long = |what: &str| format!("{what}-{}", "x".repeat(70));
        append(line(1, &long("first")));
        let seen = Seen::default();
        let mut out = seen.clone();
        let follow = log(d.path(), true, None, false, &mut out);
        let writer = async {
            seen.until("first").await;
            append(line(2, &long("before-the-move")));
            std::fs::rename(&file, &older).unwrap();
            append(line(3, &long("after-the-move")));
            seen.until("after-the-move").await;
            tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        };
        tokio::select! {
            r = follow => panic!("follow ended: {r:?}"),
            () = writer => {}
        }
        let msgs: Vec<String> = seen
            .text()
            .lines()
            .map(|l| l.rsplit("  ").next().unwrap().to_string())
            .collect();
        assert_eq!(
            msgs,
            [
                long("first"),
                long("before-the-move"),
                long("after-the-move")
            ],
            "{}",
            seen.text()
        );
    }

    /// An output that fails after its first line.
    struct Gone(usize);

    impl Write for Gone {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            if self.0 == 0 {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
            self.0 -= 1;
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// `log --follow` ends once its output is gone (`| head -1`), not at
    /// the end of time (round 4, correctness 1).
    #[tokio::test]
    async fn log_follow_ends_when_its_output_is_gone() {
        let d = tempfile::tempdir().unwrap();
        let file = nerve_transport::log::file_in(d.path());
        let line = |m: &str| format!("{}\n", json!({"ts": 1000, "level": "info", "msg": m}));
        std::fs::write(&file, line("first")).unwrap();
        let mut out = Gone(1);
        let follow = log(d.path(), true, None, false, &mut out);
        let writer = async {
            tokio::time::sleep(std::time::Duration::from_millis(700)).await;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&file)
                .unwrap();
            std::io::Write::write_all(&mut f, line("second").as_bytes()).unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        };
        tokio::select! {
            r = follow => assert_eq!(r, Ok(())),
            () = writer => panic!("the follow did not end"),
        }
    }

    /// The log is read from plain files only: a link in the center's
    /// folder (on Windows the service's account may make one where an
    /// administrator reads) shows nothing of its target, and a pipe does
    /// not make the command wait (round 2 of #213's second pass, security 2).
    #[cfg(unix)]
    #[tokio::test]
    async fn the_log_is_not_read_through_a_link_or_a_pipe() {
        let d = tempfile::tempdir().unwrap();
        let state = d.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        let secret = d.path().join("secret.jsonl");
        std::fs::write(
            &secret,
            format!("{}\n", json!({"ts": 0, "level": "info", "msg": "secret"})),
        )
        .unwrap();
        let file = nerve_transport::log::file_in(&state);
        std::os::unix::fs::symlink(&secret, &file).unwrap();
        let mut out = Vec::new();
        let e = log(&state, false, None, false, &mut out).await.unwrap_err();
        assert!(out.is_empty(), "{}", String::from_utf8_lossy(&out));
        assert!(!e.contains("secret"), "{e}");
        std::fs::remove_file(&file).unwrap();
        let fifo = std::ffi::CString::new(file.to_str().unwrap()).unwrap();
        // SAFETY: a plain call with a valid path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            log(&state, false, None, false, &mut Vec::new()),
        )
        .await
        .expect("log waited on a pipe");
        assert!(read.is_err());
    }

    /// `token new` shows the label the center kept, which it cuts at 60
    /// bytes, as `token rm` finds the token by it (round 2 of #213's
    /// second pass, correctness 6).
    #[test]
    fn a_token_is_known_by_the_label_the_center_kept() {
        let made = json!({"id": "t1", "token": "nrv_abc"});
        let kept = "x".repeat(59) + "…";
        let page = new_token_page(&made, &kept, &json!({"mode": "off"}), true, &admin)
            .render(Style::PLAIN);
        assert!(page.contains(&format!("  Label       {kept}\n")), "{page}");
        let tokens = json!([{"id": "t1", "label": kept, "created_ms": 0}]);
        assert_eq!(token_id(&tokens, &kept).unwrap(), "t1");
    }
}
