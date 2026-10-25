//! What the pages show, made from the CLI's JSON answers
//! (docs/user/commands.md): the words, their tones, and the arguments of the
//! commands the buttons run. Nothing here decides anything about the node;
//! it only says what the node said, for people.

use std::path::{Path, PathBuf};

use serde_json::Value;
use slint::{ModelRc, SharedString, VecModel};

use crate::{
    AuditRow, CapRow, CenterRow, FolderRow, LogRow, NodeStatus, PairPreview, RelayNodeRow, Tone,
    TunnelRow,
};

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or_default()
}

fn text_model(items: Vec<String>) -> ModelRc<SharedString> {
    ModelRc::new(VecModel::from(
        items
            .into_iter()
            .map(SharedString::from)
            .collect::<Vec<_>>(),
    ))
}

/// What the Overview says while root is the node's owner (#151).
pub const ROOT_OWNER: &str = "Root is the owner of this node: commands of user mode, and of allowlist mode as the owner, run as root. They can do everything on this machine, Nerve and its keys included, and nothing in Nerve holds them back.";

/// What the app says once the settings grant of the center `name` is given
/// (`on`) or taken. Where root is the node's owner (`root`), the center may
/// set its own mode to user, whose commands run as root, and the app says
/// so, as `center grant settings write` does.
pub fn settings_grant_said(name: &str, on: bool, root: bool) -> String {
    match (on, root) {
        (true, true) => format!(
            "{name} may change this machine's settings now. Root is the owner of this node, so {name} can set its own mode to user, and its commands then run as root."
        ),
        (true, false) => format!("{name} may change this machine's settings now."),
        (false, _) => format!("{name} can no longer change this machine's settings."),
    }
}

/// The node's status and its centers, from `status --json`.
pub fn status(v: &Value, now_ms: u64) -> (NodeStatus, Vec<CenterRow>) {
    let running = v["daemon"] == "running";
    let locked = v["locked"] == true;
    let centers: Vec<CenterRow> = v["centers"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|c| center(c, running, now_ms))
        .collect();
    let connected = v["centers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| c["status"] == "connected")
        .count();
    let (state, title, detail, tone) = match (locked, running) {
        (true, _) => (
            "locked",
            "Locked",
            "Every link ended. Nothing runs until you unlock.",
            Tone::Danger,
        ),
        (false, true) => (
            "running",
            "Running",
            "Each call of a center is checked against your rules.",
            Tone::Ok,
        ),
        (false, false) => (
            "stopped",
            "Not running",
            "No center reaches this machine.",
            Tone::Warn,
        ),
    };
    let limits = &v["command_limits"];
    let mut warnings = Vec::new();
    let (mut limits_off, mut limits_restart) = (String::new(), false);
    let mut held = true;
    if running {
        if let Some(why) = v["folder_commands_off"].as_str() {
            warnings.push(format!("Folder mode runs no command: {why}."));
        }
        let lost: Vec<&str> = limits["lost"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        if !lost.is_empty() {
            warnings.push(format!(
                "No command runs: the cgroup lost its {} control. Restart the service.",
                lost.join(", ")
            ));
        } else if let Some(why) = limits["off"].as_str() {
            held = false;
            (limits_off, limits_restart) = limits_line(why);
        }
        if v["keyring_failed"] == true {
            warnings.push(
                "The node found no keyring at its start. Restart it once the keyring runs.".into(),
            );
        }
    }
    // Root as the owner is said whether the node runs or not: what runs as
    // the owner runs as root.
    if v["owner_is_root"] == true {
        warnings.push(ROOT_OWNER.into());
    }
    let n = |k: &str| limits[k].as_u64().unwrap_or_default();
    let limits_text = if held || limits_restart || !limits_off.is_empty() {
        format!(
            "{} MiB · {} % · {}",
            n("memory_mb"),
            n("cpu_percent"),
            n("processes")
        )
    } else {
        "Not held here yet".to_string()
    };
    let status = NodeStatus {
        state: state.into(),
        title: title.into(),
        detail: detail.into(),
        tone,
        confinement: s(&v["confinement"]).into(),
        centers: centers.len() as i32,
        connected: connected as i32,
        sudo_on: v["sudo"] == "on",
        limits: limits_text.into(),
        limits_off: limits_off.into(),
        limits_restart,
        warnings: text_model(warnings),
    };
    (status, centers)
}

/// Why commands run without their limits (`command_limits.off`), in one
/// short line, and whether a restart of the service is what may help. A
/// platform that holds none yet (Windows) is no warning: the Overview's
/// tile says it.
fn limits_line(why: &str) -> (String, bool) {
    if why.contains("on this platform") {
        return (String::new(), false);
    }
    if why.contains("no cgroup v2") {
        return ("This machine has no cgroup v2 for them.".into(), false);
    }
    (
        "The service has no cgroup of its own for them. Restart it; the Log says why if it stays."
            .into(),
        true,
    )
}

/// The check before a pairing (`center add --json` without `--yes`), in the
/// app's words: whether Pair can work, and why not.
pub fn pair_preview(v: &Value) -> PairPreview {
    let p = &v["preview"];
    let c = &v["check"];
    let ready = c["ready"] == true;
    let check = if !ready {
        match (s(&c["reach"]), s(&c["code"])) {
            ("unreachable", _) => "The center does not answer. Check the network, or the proxy or relay this node uses.".to_string(),
            ("certificate", _) if p["pin"].is_string() => "The center's certificate is not the one the link pins. Make a new link in the center's web UI.".to_string(),
            ("certificate", _) => "The center's certificate is not one this machine trusts, and the link has no pin.".to_string(),
            (_, "used") => "A machine paired with this code already. Make a new link in the center's web UI.".to_string(),
            (_, "gone") => "The code expired or is out of tries. Make a new link in the center's web UI.".to_string(),
            _ => sentence(s(&c["problem"])),
        }
    } else if c["code"] == "open" {
        "The center answers and the code is valid.".to_string()
    } else {
        "The center answers. It did not say whether the code is still valid.".to_string()
    };
    PairPreview {
        center: s(&p["center"]).into(),
        tls: p["tls"] == true,
        pin: s(&p["pin"]).into(),
        name: s(&p["name"]).into(),
        ready,
        check: check.into(),
    }
}

/// The first letter in upper case.
fn sentence(t: &str) -> String {
    let mut c = t.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

/// One center of `status --json`: its link in words, its mode, its grant.
fn center(c: &Value, running: bool, now_ms: u64) -> CenterRow {
    let link = s(&c["status"]);
    let (label, tone, note, note_tone) = if c["revoked"] == true {
        (
            "Revoked".to_string(),
            Tone::Danger,
            "The center revoked this machine. Unpair it, and pair again to use it.".to_string(),
            Tone::Danger,
        )
    } else if c["unknown"] == true {
        (
            "Not known".to_string(),
            Tone::Danger,
            "The center no longer knows this machine. Unpair it and pair again.".to_string(),
            Tone::Danger,
        )
    } else if c["paused"] == true || link == "paused" {
        (
            "Paused".to_string(),
            Tone::Neutral,
            String::new(),
            Tone::Neutral,
        )
    } else if !running {
        (
            "Not linked".to_string(),
            Tone::Neutral,
            String::new(),
            Tone::Neutral,
        )
    } else {
        match link {
            "connected" => (
                "Connected".to_string(),
                Tone::Ok,
                String::new(),
                Tone::Neutral,
            ),
            "connecting" => (
                "Connecting".to_string(),
                Tone::Warn,
                String::new(),
                Tone::Neutral,
            ),
            "stopped" => (
                "Stopped".to_string(),
                Tone::Neutral,
                String::new(),
                Tone::Neutral,
            ),
            l if l.starts_with("link lost") => (
                "Reconnecting".to_string(),
                Tone::Warn,
                String::new(),
                Tone::Neutral,
            ),
            "not connected" | "" => (
                "Not connected".to_string(),
                Tone::Warn,
                String::new(),
                Tone::Neutral,
            ),
            // An error: its kind on the pill, the whole of it below.
            l => {
                let head = l.split(':').next().unwrap_or(l);
                let head = head.split(" (").next().unwrap_or(head);
                (sentence(head), Tone::Danger, sentence(l), Tone::Warn)
            }
        }
    };
    let mode = s(&c["mode"]);
    let mut detail = match mode {
        "allowlist" => "Only what an allow rule names.".to_string(),
        "folder" => "What each of its folders allows.".to_string(),
        "user" => "Anything you may do, protected files aside.".to_string(),
        _ => String::new(),
    };
    if mode != "allowlist"
        && let Some(until) = c["until"].as_u64()
        && until > now_ms
    {
        detail.push_str(&format!(" Back to allowlist {}.", ahead(until - now_ms)));
    }
    CenterRow {
        name: s(&c["name"]).into(),
        url: s(&c["url"]).into(),
        link: label.into(),
        link_tone: tone,
        mode: format!("{} mode", sentence(mode)).into(),
        mode_detail: detail.into(),
        settings_write: c["settings"] == "write",
        paused: c["paused"] == true,
        note: note.into(),
        note_tone,
    }
}

/// When a center's folder or user mode ends, in words; nothing without an
/// end.
pub fn mode_until(c: &Value, now_ms: u64) -> String {
    match c["until"].as_u64() {
        Some(until) if until > now_ms && c["mode"] != "allowlist" => {
            format!("Back to allowlist mode {}.", ahead(until - now_ms))
        }
        _ => String::new(),
    }
}

/// The folders of `folder ls --json`.
pub fn folders(v: &Value) -> Vec<FolderRow> {
    v["folders"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|f| FolderRow {
            path: s(&f["path"]).into(),
            read: f["read"] == true,
            write: f["write"] == true,
            execute: f["execute"] == true,
        })
        .collect()
}

/// The errors of the node's folder grants (`status`'s
/// `folder_grants.errors`, each about the path it begins with) that concern
/// `folders`, a center's (`~` the owner's `home`): a path inside one of
/// them, or above it on the way. One that names no path is the node's and
/// concerns every center.
pub fn grant_errors_for(errors: &[String], folders: &[String], home: &Path) -> Vec<String> {
    use nerve_policy::paths::within;
    let folders: Vec<PathBuf> = folders
        .iter()
        .map(|f| match f.strip_prefix("~/") {
            Some(rest) => home.join(rest),
            None if f == "~" => home.to_path_buf(),
            None => PathBuf::from(f),
        })
        .collect();
    errors
        .iter()
        .filter(|e| match e.split_once(": ") {
            Some((p, _)) if p.starts_with('/') => {
                let p = Path::new(p);
                folders.iter().any(|f| within(p, f) || within(f, p))
            }
            _ => true,
        })
        .map(|e| e.to_string())
        .collect()
}

/// The node's folder-grant errors (`status`'s `folder_grants`) split by
/// whether they are about access `nerve-run` keeps although it should have
/// lost it (`stale`: folders whose entries could not be taken off, or the
/// node's record of them). Those, with the path itself where no error names
/// it, go on every center whose commands run as `nerve-run`, as none of
/// them runs while one is left, also when the folder is no center's any
/// more; the others are for the centers whose folders they concern
/// ([`grant_errors_for`]).
pub fn stale_grants(stale: &[String], errors: &[String]) -> (Vec<String>, Vec<String>) {
    use nerve_policy::paths::within;
    let about = |e: &str, s: &str| match e.split_once(": ") {
        Some((p, _)) => within(Path::new(p), Path::new(s)),
        None => false,
    };
    let mut kept = Vec::new();
    for s in stale {
        let why: Vec<String> = errors.iter().filter(|e| about(e, s)).cloned().collect();
        if why.is_empty() {
            kept.push(s.clone());
        } else {
            kept.extend(why);
        }
    }
    kept.dedup();
    let rest = errors
        .iter()
        .filter(|e| !stale.iter().any(|s| about(e, s)))
        .cloned()
        .collect();
    (kept, rest)
}

/// The rights `folder set` takes for a folder: `=rwx`, the letters that
/// are on.
pub fn rights(read: bool, write: bool, execute: bool) -> String {
    let mut r = String::from("=");
    for (on, c) in [(read, 'r'), (write, 'w'), (execute, 'x')] {
        if on {
            r.push(c);
        }
    }
    r
}

/// One list of `rule ls --json`, each rule as `rule ls` prints it: a tab or
/// line break of a rule written `\t`, `\n`, so a row stays one line.
pub fn rule_list_of(v: &Value, list: &str) -> Vec<SharedString> {
    v[list]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|r| SharedString::from(nerve_policy::rules::escape_controls(r)))
        .collect()
}

/// Whether the deny list of `rule ls --json` lacks a rule of the guard a
/// new pairing gets (`nerve-node rule guard`).
pub fn guard_missing(v: &Value) -> bool {
    let deny: Vec<String> = v["deny"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();
    !nerve_policy::rules::guard_missing(&deny).is_empty()
}

/// Whether the deny list of `rule ls --json` still holds a text of the
/// guard from before it read commands (`nerve-node rule guard` replaces it).
pub fn guard_older(v: &Value) -> bool {
    let deny: Vec<String> = v["deny"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();
    nerve_policy::rules::guard_older(&deny)
}

/// Why the keys cannot go into the system keyring here, by the `reason` of
/// `config get machine.secret_storage --json`.
pub fn no_keyring(reason: &str) -> &'static str {
    match reason {
        "windows-service" => "Not on Windows: the service would not find them in a keyring.",
        _ => "No keyring answers for the node's account.",
    }
}

/// What the app shows after `center rotate-key` gave `name` this machine's
/// new key (`said["public_key"]`): that the center has it, and, in the
/// app's words instead of the CLI's command line, whether the center still
/// takes the old one, after `--end-grace` (`ended`) or without it; and the
/// key apart, to compare with what the center shows.
pub fn new_key(name: &str, said: &Value, ended: Option<Result<Value, String>>) -> (String, String) {
    let then = match ended {
        None => format!("The old key is deleted here. {name} takes it for 7 more days."),
        Some(Ok(_)) => format!("The old key is deleted here, and {name} no longer takes it."),
        Some(Err(e)) => {
            format!("The old key is deleted here, but {name} still takes it for 7 more days: {e}")
        }
    };
    (
        format!("{name} has this machine's new key: nothing needs to be copied.\n\n{then}"),
        s(&said["public_key"]).to_string(),
    )
}

/// What `backup` wrote (`said["backup"]`), in the app's words: where, what
/// it holds, and what it left out and why; for keys in the keyring the
/// backup dialog's own choice, not the CLI's flag.
pub fn backup_written(said: &Value) -> String {
    let b = &said["backup"];
    let names = |v: &Value| -> Vec<String> {
        v.as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    };
    let centers = names(&b["centers"]);
    let pairing = match centers.len() {
        0 => ", paired with no center".to_string(),
        _ => format!(", with the pairing of {}", and_list(&centers)),
    };
    let saved = names(&b["saved"]);
    let keys = match saved.len() {
        0 => String::new(),
        _ => format!(", and {}", and_list(&saved)),
    };
    let mut text = format!(
        "The backup is in {}.\n\nIt holds the node's settings{pairing}{keys}.",
        s(&b["file"])
    );
    let left = |why: &str| -> Vec<String> {
        b["left_out"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|l| l["why"] == why)
            .map(|l| s(&l["what"]).to_string())
            .collect()
    };
    for (why, one, more) in [
        (
            "keyring",
            "is in the system keyring, so it is not in the file. To take it too, back up again with \"Include the keys in the system keyring\".",
            "are in the system keyring, so they are not in the file. To take them too, back up again with \"Include the keys in the system keyring\".",
        ),
        (
            "does-not-fit",
            "does not fit the node's settings, so it is not in the file.",
            "do not fit the node's settings, so they are not in the file.",
        ),
        (
            "missing",
            "is not in the file: this node has none.",
            "are not in the file: this node has none.",
        ),
    ] {
        let what = left(why);
        let said = if what.len() > 1 { more } else { one };
        if !what.is_empty() {
            text.push_str(&format!("\n{} {said}", sentence(&and_list(&what))));
        }
    }
    text.push_str("\n\nThe file is sealed with your passphrase. Keep both: without the passphrase nobody can open the file, you included.");
    text
}

/// `a`, `a and b`, `a, b and c`.
fn and_list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// The link of `relay add` or `relay token` (`said["token"]`), in the
/// app's words: what the other node may do and where it pastes the link,
/// and the link to copy, which holds the relay's address, the node's name
/// and token and the pin; a node without the app pastes it into `proxy set`.
pub fn relay_token(said: &Value) -> (String, String) {
    let t = &said["token"];
    let node = s(&t["node"]);
    let mut text = format!(
        "{node} may reach {} through this relay. On {node}, paste this link under Relay, Connect.",
        s(&t["reach"])
    );
    if t["new_pin"] == true {
        text.push_str(
            " The relay has a new certificate: the other nodes behind it need a new link too.",
        );
    }
    if t["relay_off"] == true {
        text.push_str(" The relay is off: turn it on first.");
    }
    (text, s(&t["link"]).to_string())
}

/// What `restore` did (`said["restored"]`), in the app's words: the
/// centers, what to pair again, and what to set again and where. `started`
/// says what became of the node: the app started it again, or it waits.
pub fn restored(said: &Value, started: &str) -> String {
    let r = &said["restored"];
    let names = |k: &str| -> Vec<&str> {
        r[k].as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect()
    };
    let centers = names("centers");
    let mut lines = vec![if centers.is_empty() {
        "The node's settings and keys are restored; it is paired with no center.".to_string()
    } else {
        format!(
            "The node's settings and keys are restored, with the pairing of {}.",
            centers.join(", ")
        )
    }];
    for c in names("no_key") {
        lines.push(format!(
            "{c}: its key was not in the backup. Unpair {c} on the Centers page and pair it again."
        ));
    }
    let mut said = Vec::new();
    for n in r["notes"].as_array().into_iter().flatten() {
        let center = s(&n["center"]);
        let line = match s(&n["fix"]) {
            "proxy" => "The proxy is not restored whole: set it again under Settings, Network, Proxy.".into(),
            "sudo" => "Sudo is off: its password is in no backup. Turn it on again on the Permissions page.".into(),
            "sudo-file" => "Sudo is off, but the administrator's password it kept could not be deleted: turn sudo on and off again on the Permissions page.".into(),
            "pin" => format!("The pin of {center} here differed from the backup's, and the restore took the backup's. If the node does not link to {center}, set center.{center}.pin under Settings, Advanced."),
            "relay" => "The relay's TLS key was not in the backup: turn the relay on again on the Relay page; the nodes behind it need new links.".into(),
            _ => full_sentence(s(&n["text"])),
        };
        // Several notes can ask for the same: it is said once.
        if !said.contains(&line) {
            said.push(line);
        }
    }
    lines.extend(said);
    // What it did, what to do, and the node, each a paragraph.
    let mut text = lines[0].clone();
    if lines.len() > 1 {
        text.push_str("\n\n");
        text.push_str(&lines[1..].join("\n"));
    }
    format!("{text}\n\n{started}")
}

/// What became of the service the app stopped for a restore and started
/// again (`started`): with what is restored, or, after a restore that
/// failed, which then put everything back, as it was.
pub fn started_after_restore(restored: bool, started: Result<(), &str>) -> String {
    match (restored, started) {
        (true, Ok(())) => "The node started again, with what is restored.".into(),
        (false, Ok(())) => "Nothing is restored: the node started again as it was.".into(),
        (true, Err(e)) => format!("The node did not start again: {e}. Start it on the Overview."),
        (false, Err(e)) => format!(
            "Nothing is restored, and the node did not start again: {e}. Start it on the Overview."
        ),
    }
}

/// `text` as a sentence: its first letter up, a full stop at its end.
fn full_sentence(text: &str) -> String {
    let mut out = sentence(text);
    if !out.ends_with('.') {
        out.push('.');
    }
    out
}

/// Whether a rule typed for the allow or deny list is in the pattern form
/// for files and other actions (`fs.read:~/notes/*`, `fs:~/private/*`),
/// which `rule add` refuses as a command and `config add` takes: the test of
/// nerve-node's `rule add` (`List::entry`). A single letter before the `:`
/// is a drive (`C:\tools\x.exe`), not a capability.
pub fn pattern_rule(text: &str) -> bool {
    text.trim().split_once(':').is_some_and(|(scope, _)| {
        (scope.contains('.') || scope.len() > 1) && nerve_policy::rules::valid_scope(scope)
    })
}

/// The capability switches of `cap ls --json`: each capability the node
/// knows, then its actions, with what is set (on when nothing is).
pub fn caps(v: &Value) -> Vec<CapRow> {
    let setting = |name: &str| match v["caps"][name].as_str() {
        Some("off") => (1, true),
        Some("hidden") => (2, true),
        Some(_) => (0, true),
        None => (0, false),
    };
    let mut rows = Vec::new();
    for (cap, actions) in v["known"].as_object().into_iter().flatten() {
        let (s, set) = setting(cap);
        rows.push(CapRow {
            name: cap.as_str().into(),
            action: false,
            setting: s,
            set,
        });
        for a in actions
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            let name = format!("{cap}.{a}");
            let (s, set) = setting(&name);
            rows.push(CapRow {
                name: name.into(),
                action: true,
                setting: s,
                set,
            });
        }
    }
    rows
}

/// The word `cap set` takes for a switch.
pub fn cap_word(setting: i32) -> &'static str {
    match setting {
        1 => "off",
        2 => "hidden",
        _ => "on",
    }
}

/// The lines of the log to show, from `newest` first: all of them, or the
/// errors and warnings only.
pub fn log_rows(newest: &[Value], problems_only: bool, now_ms: u64) -> Vec<LogRow> {
    newest
        .iter()
        .filter(|e| !problems_only || matches!(s(&e["level"]), "error" | "warn"))
        .map(|e| {
            let ts = e["ts"].as_u64().unwrap_or_default();
            let level = s(&e["level"]);
            let mut msg = s(&e["msg"]).to_string();
            if let Some(n) = e["node"].as_str() {
                msg = format!("{msg} ({n})");
            }
            LogRow {
                tone: match level {
                    "error" => Tone::Danger,
                    "warn" => Tone::Warn,
                    "info" => Tone::Accent,
                    _ => Tone::Neutral,
                },
                level: match level {
                    "error" => "Error",
                    "warn" => "Warning",
                    "info" => "Info",
                    "debug" => "Debug",
                    other => other,
                }
                .into(),
                msg: msg.into(),
                when: ago(ts, now_ms).into(),
                when_exact: exact(ts).into(),
            }
        })
        .collect()
}

/// Whether the proxy of `proxy ls --json` is a relay: https, with a pin
/// and a login (its node's name); its address and that name.
pub fn relay_of(proxy: &Value) -> (bool, String, String) {
    let url = s(&proxy["proxy"]);
    let login = s(&proxy["login"]);
    match url.strip_prefix("https://") {
        Some(rest) if proxy["pin"].is_string() && !login.is_empty() => (
            true,
            rest.trim_end_matches('/').to_string(),
            login.to_string(),
        ),
        _ => (false, String::new(), String::new()),
    }
}

/// An error of the CLI as a sentence.
pub fn sentence_of(e: &str) -> String {
    let mut t = sentence(e);
    if !t.ends_with('.') {
        t.push('.');
    }
    t
}

/// The tunnels of `relay ls --json` the relay carries now, each since when.
pub fn tunnels(v: &Value, now_ms: u64) -> Vec<TunnelRow> {
    v["tunnels"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|t| {
            let since = t["since_ms"].as_u64().unwrap_or(now_ms);
            TunnelRow {
                node: s(&t["node"]).into(),
                center: s(&t["center"]).into(),
                from: s(&t["from"]).into(),
                since: format!(
                    "for {}",
                    nerve_transport::log::span(std::time::Duration::from_millis(
                        now_ms.saturating_sub(since)
                    ))
                )
                .into(),
            }
        })
        .collect()
}

/// The nodes of `relay ls --json` that may use the relay.
pub fn relay_nodes(v: &Value) -> Vec<RelayNodeRow> {
    v["nodes"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|n| {
            let centers: Vec<&str> = n["centers"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            let open = v["tunnels"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|t| t["node"] == n["name"])
                .count();
            RelayNodeRow {
                live: match open {
                    0 => String::new(),
                    1 => "1 link".into(),
                    n => format!("{n} links"),
                }
                .into(),
                centers: ModelRc::new(VecModel::from(
                    centers
                        .iter()
                        .map(|c| SharedString::from(*c))
                        .collect::<Vec<_>>(),
                )),
                own_limits: n["own_limits"] == true,
                max_links: n["max_links"].as_i64().unwrap_or_default() as i32,
                max_opens: n["max_opens_per_minute"].as_i64().unwrap_or_default() as i32,
                name: s(&n["name"]).into(),
                reach: if centers.is_empty() {
                    "may reach every https center of this node".to_string()
                } else {
                    format!("may reach {}", centers.join(", "))
                }
                .into(),
                limits: if n["own_limits"] == true {
                    format!(
                        "its own limits: {} tunnels at once, {} opened a minute",
                        n["max_links"], n["max_opens_per_minute"]
                    )
                } else {
                    String::new()
                }
                .into(),
            }
        })
        .collect()
}

/// A setting's value as `config get --json` gave it, for people: a text as
/// it is, anything else as JSON.
pub fn setting(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => serde_json::to_string_pretty(other).unwrap_or_default(),
    }
}

/// A proxy URL and the password the owner typed, as `proxy set` takes them
/// with `--password-stdin`: a password in the URL (`user:password@`) moves
/// out of it, unless one was typed. `None`: no password.
pub fn proxy_login(url: &str, typed: &str) -> (String, Option<String>) {
    let mut url = url.to_string();
    let mut password = (!typed.is_empty()).then(|| typed.to_string());
    if let Some(scheme) = url.find("://")
        && let Some(at) = url.rfind('@')
        && at > scheme
        && let Some(colon) = url[scheme + 3..at].find(':').map(|c| c + scheme + 3)
    {
        let given = url[colon + 1..at].to_string();
        url.replace_range(colon..at, "");
        // A password in a URL is %-escaped; on stdin it is taken as it is.
        if password.is_none() {
            password = Some(pct_decode(&given));
        }
    }
    (url, password)
}

/// `%XX` escapes undone; a broken one stays as it is.
fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = (b[i] == b'%')
            .then(|| std::str::from_utf8(b.get(i + 1..i + 3)?).ok())
            .flatten()
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match hex {
            Some(x) => {
                out.push(x);
                i += 3;
            }
            None => {
                out.push(b[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A time ahead, in words.
fn ahead(ms: u64) -> String {
    let min = ms / 60_000;
    match min {
        0 => "in less than a minute".into(),
        1..=59 => format!("in {min} min"),
        60..=2879 => format!("in {} h", min / 60),
        _ => format!("in {} days", min / 1440),
    }
}

/// A time gone, in words.
pub fn ago(ts_ms: u64, now_ms: u64) -> String {
    let secs = now_ms.saturating_sub(ts_ms) / 1000;
    match secs {
        0..=44 => "just now".into(),
        45..=3599 => format!("{} min ago", (secs / 60).max(1)),
        3600..=86_399 => format!("{} h ago", secs / 3600),
        86_400..=172_799 => "yesterday".into(),
        _ => format!("{} days ago", secs / 86_400),
    }
}

/// A time as a date and the time of day, in UTC.
pub fn exact(ts_ms: u64) -> String {
    let secs = ts_ms / 1000;
    let (days, rest) = (secs / 86_400, secs % 86_400);
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// A setting's value as one short piece of text.
fn shown(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "nothing".into(),
        other => other.to_string(),
    }
}

/// The most changed settings one entry names; the rest are counted.
const CHANGES_SHOWN: usize = 6;

/// The settings that differ between `old` and `new` under `key`, each as
/// `key.of.it: old → new`. The log keeps a changed table or list whole
/// (the centers, a policy), so it is followed down to what changed in it;
/// a list of named entries (the centers) by their names.
fn changed(key: &str, old: &Value, new: &Value, out: &mut Vec<String>) {
    if old == new {
        return;
    }
    let join = |k: &str| {
        if key.is_empty() {
            k.to_string()
        } else {
            format!("{key}.{k}")
        }
    };
    if let (Some(a), Some(b)) = (old.as_object(), new.as_object()) {
        let mut keys: Vec<&String> = a.keys().chain(b.keys()).collect();
        keys.sort();
        keys.dedup();
        for k in keys {
            let none = Value::Null;
            changed(
                &join(k),
                a.get(k).unwrap_or(&none),
                b.get(k).unwrap_or(&none),
                out,
            );
        }
        return;
    }
    if let (Some(a), Some(b)) = (named(old), named(new))
        && !(a.is_empty() && b.is_empty())
    {
        let mut names: Vec<&String> = Vec::new();
        for (n, _) in a.iter().chain(b.iter()) {
            if !names.contains(&n) {
                names.push(n);
            }
        }
        fn find<'a>(l: &'a [(String, Value)], n: &str) -> Option<&'a Value> {
            l.iter().find(|(m, _)| m == n).map(|(_, v)| v)
        }
        for n in names {
            match (find(&a, n), find(&b, n)) {
                (Some(x), Some(y)) => changed(&join(n), x, y, out),
                (None, Some(_)) => out.push(format!("{} added", join(n))),
                (Some(_), None) => out.push(format!("{} removed", join(n))),
                (None, None) => {}
            }
        }
        return;
    }
    // A list of words, such as rules: what came and what went.
    let words = |v: &Value| -> Option<Vec<String>> {
        if v.is_null() {
            return Some(Vec::new());
        }
        v.as_array()?
            .iter()
            .map(|e| e.as_str().map(str::to_string))
            .collect()
    };
    if (old.is_array() || new.is_array())
        && let (Some(a), Some(b)) = (words(old), words(new))
    {
        let added: Vec<&str> = b
            .iter()
            .filter(|w| !a.contains(w))
            .map(String::as_str)
            .collect();
        let removed: Vec<&str> = a
            .iter()
            .filter(|w| !b.contains(w))
            .map(String::as_str)
            .collect();
        if !added.is_empty() {
            out.push(format!("{key} + {}", added.join(", ")));
        }
        if !removed.is_empty() {
            out.push(format!("{key} − {}", removed.join(", ")));
        }
        return;
    }
    out.push(format!("{key}: {} → {}", short(old), short(new)));
}

/// A list whose entries all have a name (the centers), by name; nothing
/// for no list.
fn named(v: &Value) -> Option<Vec<(String, Value)>> {
    if v.is_null() {
        return Some(Vec::new());
    }
    v.as_array()?
        .iter()
        .map(|e| Some((e["name"].as_str()?.to_string(), e.clone())))
        .collect()
}

/// A value in a line of its own: cut when long.
fn short(v: &Value) -> String {
    let t = shown(v);
    match t.char_indices().nth(60) {
        Some((at, _)) => format!("{}…", &t[..at]),
        None => t,
    }
}

/// What the Audit page shows of the entries it read: the decision (0 all,
/// 1 allowed calls, 2 refused calls and refused config files, 3 settings
/// changes), one center and one action (empty: every one), words to find
/// in the target and the reason (a change: its keys), and the order.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AuditFilter {
    pub decision: i32,
    pub center: String,
    pub action: String,
    pub text: String,
    pub oldest_first: bool,
}

impl AuditFilter {
    pub fn is_set(&self) -> bool {
        self.decision != 0
            || !self.center.is_empty()
            || !self.action.is_empty()
            || !self.text.trim().is_empty()
    }
}

/// The Audit page for a filter: the rows (at most `limit`), how many
/// entries each decision has under the other filters, how many match
/// them all, and the centers and actions there are to pick.
#[derive(Debug, Default)]
pub struct AuditView {
    pub rows: Vec<AuditRow>,
    pub counts: [usize; 4],
    pub matches: usize,
    pub centers: Vec<String>,
    pub actions: Vec<String>,
}

/// The decision of an entry as the filter counts it (see [`AuditFilter`]);
/// 0 for an entry that is none of the three.
fn decision_of(e: &Value) -> i32 {
    if e.get("changes").is_some() {
        3
    } else if e["decision"] == "forbidden" || (e["kind"] == "config" && e["event"] == "refused") {
        2
    } else if e["decision"] == "allowed" {
        1
    } else {
        0
    }
}

/// The center an entry is about: a call's, a key's, a relay tunnel's, or
/// the one that changed the settings.
fn center_of(e: &Value) -> &str {
    match e["center"].as_str() {
        Some(c) => c,
        None => s(&e["by"]).strip_prefix("center ").unwrap_or_default(),
    }
}

/// A call's capability and action, `exec.run`.
fn action_of(e: &Value) -> Option<String> {
    (e.get("changes").is_none() && e["cap"].is_string() && e["action"].is_string())
        .then(|| format!("{}.{}", s(&e["cap"]), s(&e["action"])))
}

/// Whether every word of `text` is in the entry's target or reason (a
/// change: its keys), in any case.
fn finds(e: &Value, text: &str) -> bool {
    let mut hay = format!("{} {} {}", s(&e["target"]), s(&e["reason"]), s(&e["file"]));
    for c in e["changes"].as_array().into_iter().flatten() {
        hay.push(' ');
        hay.push_str(s(&c["key"]));
    }
    let hay = hay.to_lowercase();
    text.split_whitespace()
        .all(|w| hay.contains(&w.to_lowercase()))
}

/// The Audit page for `filter`, from the `newest` entries first; the
/// rows keep their entry's index in `newest` for the buttons.
pub fn audit_view(
    newest: &[Value],
    centers: &[String],
    filter: &AuditFilter,
    limit: usize,
    now_ms: u64,
) -> AuditView {
    let mut view = AuditView::default();
    let mut picked = Vec::new();
    for (i, e) in newest.iter().enumerate() {
        let center = center_of(e);
        if !center.is_empty() && !view.centers.iter().any(|c| c == center) {
            view.centers.push(center.to_string());
        }
        let action = action_of(e);
        if let Some(a) = &action
            && !view.actions.contains(a)
        {
            view.actions.push(a.clone());
        }
        let others = (filter.center.is_empty() || center == filter.center)
            && (filter.action.is_empty() || action.as_deref() == Some(filter.action.as_str()))
            && finds(e, &filter.text);
        if !others {
            continue;
        }
        let decision = decision_of(e);
        view.counts[0] += 1;
        if decision > 0 {
            view.counts[decision as usize] += 1;
        }
        if filter.decision == 0 || filter.decision == decision {
            picked.push(i);
        }
    }
    view.centers.sort();
    view.actions.sort();
    view.matches = picked.len();
    if filter.oldest_first {
        picked.reverse();
    }
    view.rows = picked
        .into_iter()
        .take(limit)
        .map(|i| audit_row(&newest[i], i, centers, now_ms))
        .collect();
    view
}

fn audit_row(e: &Value, index: usize, centers: &[String], now_ms: u64) -> AuditRow {
    let ts = e["ts"].as_u64().unwrap_or_default();
    let mut row = AuditRow {
        kind: "call".into(),
        tone: Tone::Neutral,
        title: SharedString::new(),
        badge: SharedString::new(),
        center: s(&e["center"]).into(),
        target: SharedString::new(),
        detail: SharedString::new(),
        when: ago(ts, now_ms).into(),
        when_exact: exact(ts).into(),
        rules: false,
        rules_why: SharedString::new(),
        index: index as i32,
    };
    if e.get("changes").is_some() {
        let mut changes = Vec::new();
        for c in e["changes"].as_array().into_iter().flatten() {
            changed(s(&c["key"]), &c["old"], &c["new"], &mut changes);
        }
        let more = changes.len().saturating_sub(CHANGES_SHOWN);
        changes.truncate(CHANGES_SHOWN);
        if more > 0 {
            changes.push(format!("{more} more"));
        }
        row.kind = "settings".into();
        row.tone = Tone::Accent;
        row.title = "Settings changed".into();
        row.badge = format!("version {}", shown(&e["version"])).into();
        row.center = SharedString::new();
        // A local change names the account that made it, when known.
        let by = match e["user"].as_str() {
            Some(user) => user.to_string(),
            None => shown(&e["by"]),
        };
        row.detail = format!("By {by}. {}", changes.join("; ")).into();
        return row;
    }
    match s(&e["kind"]) {
        "node" => {
            let steps: Vec<&str> = e["steps"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            row.kind = "node".into();
            row.title = format!("Node {}", s(&e["event"])).into();
            let mut detail = steps.join("; ");
            if let Some(err) = e["error"].as_str() {
                row.tone = Tone::Danger;
                row.badge = "Failed".into();
                detail = format!("{detail} Stopped: {err}");
            }
            row.detail = detail.trim().to_string().into();
        }
        "relay" => {
            let span = e["end"]
                .as_u64()
                .unwrap_or(0)
                .saturating_sub(e["start"].as_u64().unwrap_or(0));
            row.kind = "relay".into();
            row.title = "Relay tunnel".into();
            row.detail = format!(
                "{} from {} to center {}: {} after {} s ({} bytes up, {} down)",
                shown(&e["node"]),
                shown(&e["from"]),
                shown(&e["center"]),
                shown(&e["reason"]),
                span / 1000,
                shown(&e["up"]),
                shown(&e["down"]),
            )
            .into();
        }
        "config" => {
            row.kind = "config".into();
            row.title = format!("Config {}", s(&e["event"])).into();
            if e["event"] == "refused" {
                row.tone = Tone::Warn;
                row.badge = "Refused".into();
            }
            row.target = s(&e["file"]).into();
            row.detail = sentence(s(&e["reason"])).into();
        }
        "audit" => {
            row.kind = "audit".into();
            row.title = "Audit log cleared".into();
            row.detail = format!(
                "By {}. The entries before are in the file audit.jsonl.1.",
                shown(&e["user"])
            )
            .into();
        }
        "key" => {
            row.kind = "key".into();
            row.title = format!("Key {}", s(&e["event"])).into();
            row.detail = s(&e["detail"]).into();
        }
        _ => {
            let refused = e["decision"] == "forbidden";
            row.title = format!("{}.{}", s(&e["cap"]), s(&e["action"])).into();
            row.tone = if refused { Tone::Danger } else { Tone::Ok };
            row.badge = if refused { "Refused" } else { "Allowed" }.into();
            row.target = s(&e["target"]).into();
            row.detail = e["reason"]
                .as_str()
                .map(sentence)
                .unwrap_or_default()
                .into();
            let (rules, why) = rules_for(e, centers);
            row.rules = rules;
            row.rules_why = why.into();
        }
    }
    row
}

/// Whether the four buttons can make a rule for an entry, and why not: a
/// rule needs its action and target, a target cut to its start names no
/// call, and the center must still be paired.
fn rules_for(e: &Value, centers: &[String]) -> (bool, String) {
    let (cap, action, target) = (s(&e["cap"]), s(&e["action"]), s(&e["target"]));
    if cap.is_empty() || action.is_empty() || (target.is_empty() && matches!(cap, "exec" | "fs")) {
        return (false, String::new());
    }
    if nerve_policy::audit::is_cut_target(target) {
        return (
            false,
            "The target was cut to its start, so no rule can name it.".into(),
        );
    }
    if !centers.iter().any(|c| c == s(&e["center"])) {
        return (false, "The center is no longer paired here.".into());
    }
    (true, String::new())
}

/// The list a button puts an entry on: `allow` or `deny`, and the sudo
/// list in place of `allow` for a sudo command, as on the center's audit
/// page.
pub fn rule_list(e: &Value, list: &str) -> &'static str {
    let sudo = e["cap"] == "exec"
        && e["action"] == "run"
        && nerve_policy::sudo_command(s(&e["target"])).is_some();
    match list {
        "deny" => "deny",
        _ if sudo => "sudo",
        _ => "allow",
    }
}

/// The command a button runs: `rule add` with the entry's action, target
/// and center ([`rule_list`] picks the list).
pub fn rule_args(e: &Value, list: &str, wildcard: bool) -> Vec<String> {
    let mut args = vec![
        "rule".to_string(),
        "add".into(),
        rule_list(e, list).into(),
        s(&e["target"]).into(),
        format!("--action={}.{}", s(&e["cap"]), s(&e["action"])),
        format!("--center={}", s(&e["center"])),
    ];
    if wildcard {
        args.push("--wildcard".into());
    }
    args
}

#[cfg(test)]
mod tests {
    /// A pairing from before the guard read commands is told its guard is of
    /// the older kind, not that it has none.
    #[test]
    fn the_guard_of_a_pairing_is_older_or_missing() {
        let old = nerve_policy::rules::GUARD_OLD[0];
        let v = json!({"deny": [old, "exec.run:rm *"]});
        assert!(guard_missing(&v));
        assert!(guard_older(&v));
        let v = json!({"deny": ["exec.run:rm *"]});
        assert!(guard_missing(&v));
        assert!(!guard_older(&v));
        let v = json!({"deny": nerve_policy::rules::GUARD});
        assert!(!guard_missing(&v));
        assert!(!guard_older(&v));
    }

    /// A rule with a line break is one row, written as `rule ls` prints it.
    #[test]
    fn a_rule_with_a_line_break_is_one_row() {
        let v = json!({"deny": ["exec.run:a\n*", "exec.run:b\tc\r\n", "exec.run:C:\\new"]});
        let rows = rule_list_of(&v, "deny");
        let rows: Vec<&str> = rows.iter().map(|r| r.as_str()).collect();
        assert_eq!(
            rows,
            ["exec.run:a\\n*", "exec.run:b\\tc\\r\\n", "exec.run:C:\\new"]
        );
    }

    /// The relay's link in the app's words: where the other node pastes
    /// it, and the link itself to copy; no line sends the owner of this
    /// machine to a terminal.
    #[test]
    fn a_relay_link_says_where_the_other_node_pastes_it() {
        let link = "nerve://relay?address=relay.example%3A7491&node=lab-pc&token=t0k&pin=p1n";
        let v = json!({"messages": ["on lab-pc, run:"], "token": {
            "node": "lab-pc", "token": "t0k", "pin": "p1n", "link": link,
            "proxy": "https://lab-pc:t0k@relay.example:7491", "address": "relay.example:7491",
            "reach": "every https center of this node", "new_pin": false, "relay_off": true,
        }});
        let (text, copy) = relay_token(&v);
        assert_eq!(copy, link);
        assert!(
            text.contains("paste this link under Relay, Connect"),
            "{text}"
        );
        assert!(text.contains("The relay is off"), "{text}");
        assert!(!text.contains('`') && !copy.contains('`'), "{text}");
    }

    /// Why Pair cannot work, in words that say what to do; and when it can.
    #[test]
    fn the_check_before_pairing_says_why_pair_cannot_work() {
        let preview = |check: Value| {
            pair_preview(
                &json!({"preview": {"center": "https://c", "tls": true, "pin": "p"}, "check": check}),
            )
        };
        let p = preview(json!({"ready": true, "reach": "ok", "code": "open"}));
        assert!(p.ready && p.check.contains("code is valid"), "{}", p.check);
        let p = preview(json!({"ready": true, "reach": "ok", "code": "busy"}));
        assert!(p.ready && p.check.contains("did not say"), "{}", p.check);
        for (reach, code, says) in [
            ("unreachable", Value::Null, "does not answer"),
            ("certificate", Value::Null, "not the one the link pins"),
            ("ok", json!("used"), "paired with this code already"),
            ("ok", json!("gone"), "expired or is out of tries"),
        ] {
            let p = preview(json!({"ready": false, "reach": reach, "code": code, "problem": "x"}));
            assert!(!p.ready && p.check.contains(says), "{reach}: {}", p.check);
        }
    }

    /// Commands without their limits: one short line, and the restart
    /// where that may help; none on a platform that holds none yet.
    #[test]
    fn commands_without_limits_get_one_line() {
        let st = |off: &str| {
            status(
                &json!({"daemon": "running", "command_limits": {"memory_mb": 1, "off": off}}),
                0,
            )
            .0
        };
        let s1 = st(
            "the node runs outside a cgroup it may manage; start it as the installed service, or under systemd-run --user --scope -p Delegate=yes",
        );
        assert!(
            s1.limits_restart && s1.limits_off.starts_with("The service has no cgroup"),
            "{}",
            s1.limits_off
        );
        assert!(s1.limits_off.len() < 100, "{}", s1.limits_off);
        let s2 = st("this machine has no cgroup v2 (unified hierarchy)");
        assert!(!s2.limits_restart && s2.limits_off.contains("no cgroup v2"));
        let s3 = st("this node does not hold commands to their limits on this platform yet");
        assert_eq!(s3.limits_off, "");
        assert_eq!(s3.limits, "Not held here yet");
        assert_eq!(s3.warnings.row_count(), 0);
    }

    /// A restore in the app's words: the CLI's commands become the places
    /// in the app, and a note without one is kept as a sentence.
    #[test]
    fn a_restore_says_what_to_do_in_the_app() {
        let v = json!({"messages": ["Start the node. … (docs/user/backup.md)"], "restored": {
            "centers": ["home", "lab"], "kept": [], "no_key": ["lab"],
            "notes": [
                {"text": "the sudo switch is off: `nerve-node sudo on` turns it on", "fix": "sudo", "center": null},
                {"text": "the pin of center home here …: `nerve-node config set center.home.pin <pin>`", "fix": "pin", "center": "home"},
                {"text": "run `nerve-node proxy set` again", "fix": "proxy", "center": null},
                {"text": "run `nerve-node proxy set` again", "fix": "proxy", "center": null},
                {"text": "the node key for home was rotated after the backup was made", "fix": null, "center": null},
            ],
        }});
        let text = restored(&v, "The node started again.");
        assert!(text.contains("pairing of home, lab"), "{text}");
        assert!(text.contains("Unpair lab on the Centers page"), "{text}");
        assert!(text.contains("on the Permissions page"), "{text}");
        assert!(
            text.contains("set center.home.pin under Settings, Advanced"),
            "{text}"
        );
        assert_eq!(
            text.matches("Settings, Network, Proxy").count(),
            1,
            "{text}"
        );
        assert!(
            text.contains("The node key for home was rotated after the backup was made."),
            "{text}"
        );
        assert!(text.ends_with("The node started again."), "{text}");
        assert!(!text.contains('`') && !text.contains("docs/user"), "{text}");
    }

    use super::*;
    use serde_json::json;
    use slint::Model;

    const NOW: u64 = 1_760_800_000_000;

    #[test]
    fn a_new_key_is_said_without_the_command_line() {
        // What `center rotate-key --json` says (cli.rs, rotate_key).
        let said = json!({"messages": [
            "center lab took this machine's new key:",
            "  ed25519:AAAA",
            "The old key is deleted here. The center takes it for 7 more days, unless you end that now with `nerve-node center rotate-key --end-grace --center lab`.",
        ], "public_key": "ed25519:AAAA"});
        let (text, copy) = new_key("lab", &said, None);
        // The key apart, and no prose in it; nothing to copy to another node.
        assert_eq!(copy, "ed25519:AAAA");
        assert!(text.starts_with("lab has this machine's new key: nothing needs"));
        assert!(
            !text.contains("AAAA") && !text.contains("other node"),
            "{text}"
        );
        assert!(text.ends_with("lab takes it for 7 more days."), "{text}");
        assert!(!text.contains("nerve-node"), "{text}");
        let (ended, _) = new_key("lab", &said, Some(Ok(json!({}))));
        assert!(ended.ends_with("lab no longer takes it."), "{ended}");
        let (failed, _) = new_key("lab", &said, Some(Err("the link dropped".into())));
        assert!(failed.contains("still takes it") && failed.contains("the link dropped"));
    }

    /// After a restore that failed, the node the app started again runs
    /// as it was, and the app says so instead of "with what is restored".
    #[test]
    fn a_failed_restore_says_the_node_runs_as_it_was() {
        assert_eq!(
            started_after_restore(true, Ok(())),
            "The node started again, with what is restored."
        );
        let failed = started_after_restore(false, Ok(()));
        assert!(
            failed.starts_with("Nothing is restored") && !failed.contains("with what is restored"),
            "{failed}"
        );
        let neither = started_after_restore(false, Err("it timed out"));
        assert!(
            neither.starts_with("Nothing is restored") && neither.contains("it timed out"),
            "{neither}"
        );
        assert!(started_after_restore(true, Err("x")).contains("did not start again: x"));
    }

    /// What a backup wrote, in the app's words: a key the keyring kept
    /// names the dialog's choice, never the CLI's flag.
    #[test]
    fn a_backup_says_what_it_holds_in_the_apps_words() {
        // What `backup --json` says (cli.rs; backup::backup_data).
        let said = json!({"messages": ["backed up to /home/alex/n.backup", "  left out: the node key for lab (it is in the system keyring; --include-keyring takes it out)"],
            "backup": {"file": "/home/alex/n.backup", "centers": ["home", "lab"],
                "saved": ["the node key for home"],
                "left_out": [{"what": "the node key for lab", "why": "keyring"}]}});
        let text = backup_written(&said);
        assert!(
            text.starts_with("The backup is in /home/alex/n.backup."),
            "{text}"
        );
        assert!(
            text.contains(
                "It holds the node's settings, with the pairing of home and lab, and the node key for home."
            ),
            "{text}"
        );
        assert!(
            text.contains("The node key for lab is in the system keyring")
                && text.contains("\"Include the keys in the system keyring\""),
            "{text}"
        );
        assert!(!text.contains("--") && !text.contains("  "), "{text}");
        let none = json!({"backup": {"file": "/b", "centers": [], "saved": [],
            "left_out": [{"what": "the node key for a", "why": "missing"}, {"what": "the node key for b", "why": "missing"}]}});
        let text = backup_written(&none);
        assert!(
            text.contains("It holds the node's settings, paired with no center."),
            "{text}"
        );
        assert!(
            text.contains("The node key for a and the node key for b are not in the file"),
            "{text}"
        );
    }

    #[test]
    fn a_pattern_for_files_is_told_from_a_command() {
        for p in ["fs.read:~/notes/*", "fs:~/private/*", "exec.run:make *"] {
            assert!(pattern_rule(p), "{p}");
        }
        for c in [
            "cargo build",
            "C:\\tools\\x.exe",
            "git commit -m a:b",
            "echo x:y",
        ] {
            assert!(!pattern_rule(c), "{c}");
        }
    }

    #[test]
    fn a_running_node_and_its_links() {
        let v = json!({
            "daemon": "running", "locked": false, "sudo": "off",
            "confinement": "landlock abi 6",
            "command_limits": {"memory_mb": 2048, "cpu_percent": 100, "processes": 256},
            "centers": [
                {"name": "home", "url": "https://c.example", "status": "connected", "mode": "folder", "settings": "write", "paused": false},
                {"name": "lab", "url": "http://10.0.0.2:7443", "status": "cannot connect: connection refused (os error 111)", "mode": "user", "until": NOW + 3 * 3_600_000, "settings": "off", "paused": false},
                {"name": "old", "url": "x", "status": "connecting", "mode": "allowlist", "revoked": true},
            ],
        });
        let (st, centers) = status(&v, NOW);
        assert_eq!(st.state, "running");
        assert_eq!(st.tone, Tone::Ok);
        assert_eq!((st.centers, st.connected), (3, 1));
        assert_eq!(st.limits, "2048 MiB · 100 % · 256");
        assert_eq!(st.warnings.row_count(), 0);
        assert_eq!(
            (centers[0].link.as_str(), centers[0].link_tone),
            ("Connected", Tone::Ok)
        );
        assert!(centers[0].settings_write);
        assert_eq!(centers[0].mode, "Folder mode");
        assert_eq!(
            (centers[1].link.as_str(), centers[1].link_tone),
            ("Cannot connect", Tone::Danger)
        );
        assert!(
            centers[1].note.contains("connection refused"),
            "{}",
            centers[1].note
        );
        assert!(
            centers[1]
                .mode_detail
                .ends_with("Back to allowlist in 3 h."),
            "{}",
            centers[1].mode_detail
        );
        assert_eq!(centers[2].link, "Revoked");
    }

    #[test]
    fn a_stopped_or_locked_node() {
        let v = json!({"daemon": "not running", "locked": false, "sudo": "off",
            "command_limits": {"off": "the node does not run"},
            "centers": [{"name": "home", "url": "u", "status": null, "mode": "allowlist", "paused": true}]});
        let (st, centers) = status(&v, NOW);
        assert_eq!((st.state.as_str(), st.tone), ("stopped", Tone::Warn));
        // Not running is said once, not as a missing limit too.
        assert_eq!(st.warnings.row_count(), 0);
        assert_eq!(centers[0].link, "Paused");
        let v = json!({"daemon": "running", "locked": true, "centers": [],
            "folder_commands_off": "commands cannot be confined on this machine"});
        let (st, _) = status(&v, NOW);
        assert_eq!(st.state, "locked");
        assert_eq!(st.warnings.row_count(), 1);
    }

    /// Giving the settings grant where root is the owner says that the
    /// center can make itself root.
    #[test]
    fn the_settings_grant_says_root_where_root_is_the_owner() {
        let said = settings_grant_said("home", true, true);
        assert!(said.contains("home can set its own mode to user"), "{said}");
        assert!(said.contains("run as root"), "{said}");
        assert!(!settings_grant_said("home", true, false).contains("root"));
        assert!(!settings_grant_said("home", false, true).contains("root"));
    }

    /// Root as the owner is a warning on the Overview, running or not.
    #[test]
    fn root_as_the_owner_is_said() {
        for daemon in ["running", "not running"] {
            let v =
                json!({"daemon": daemon, "owner": "root", "owner_is_root": true, "centers": []});
            let (st, _) = status(&v, NOW);
            let w: Vec<SharedString> = st.warnings.iter().collect();
            assert_eq!(w, [SharedString::from(ROOT_OWNER)], "{daemon}");
            let v =
                json!({"daemon": daemon, "owner": "alice", "owner_is_root": false, "centers": []});
            assert_eq!(status(&v, NOW).0.warnings.row_count(), 0, "{daemon}");
        }
    }

    fn call(target: &str, decision: &str, center: &str) -> Value {
        json!({"ts": NOW - 120_000, "center": center, "cap": "exec", "action": "run", "target": target, "decision": decision})
    }

    #[test]
    fn the_audit_newest_first_with_buttons_where_a_rule_fits() {
        let centers = vec!["home".to_string()];
        let cut = format!(
            "{}… [cut at {n} of 600 characters]",
            "a".repeat(nerve_policy::audit::TARGET_MAX_CHARS),
            n = nerve_policy::audit::TARGET_MAX_CHARS
        );
        let entries = [
            call("git status", "allowed", "home"),
            json!({"ts": NOW, "kind": "settings", "by": "local", "version": 4,
                "changes": [{"key": "center.home.policy.mode", "old": "allowlist", "new": "user"}]}),
            call("ls", "forbidden", "gone"),
            call(&cut, "forbidden", "home"),
            json!({"ts": NOW, "center": "home", "cap": "fs", "action": "read", "target": "/etc/shadow", "decision": "forbidden", "reason": "protected path"}),
        ];
        let newest: Vec<Value> = entries.iter().rev().cloned().collect();
        let all = AuditFilter::default();
        let rows = audit_view(&newest, &centers, &all, 200, NOW).rows;
        assert_eq!(rows.len(), 5);
        assert_eq!(rows[0].title, "fs.read");
        assert_eq!(
            (rows[0].badge.as_str(), rows[0].tone),
            ("Refused", Tone::Danger)
        );
        assert_eq!(rows[0].detail, "Protected path");
        assert!(rows[0].rules);
        assert!(!rows[1].rules && rows[1].rules_why.contains("cut"));
        assert!(!rows[2].rules && rows[2].rules_why.contains("no longer paired"));
        assert_eq!(rows[3].kind, "settings");
        assert!(
            rows[3]
                .detail
                .contains("center.home.policy.mode: allowlist → user"),
            "{}",
            rows[3].detail
        );
        // A table the log keeps whole is followed down to what changed.
        let whole = json!({"ts": NOW, "kind": "settings", "by": "local", "version": 5, "changes": [{"key": "center",
            "old": [{"name": "home", "policy": {"mode": "folder"}}, {"name": "lab", "paused": false}],
            "new": [{"name": "home", "policy": {"mode": "folder", "allow": ["exec.run:cargo *"]}}, {"name": "lab", "paused": true}, {"name": "new"}]}]});
        let whole = audit_view(&[whole], &centers, &all, 200, NOW).rows;
        assert_eq!(
            whole[0].detail,
            "By local. center.home.policy.allow + exec.run:cargo *; center.lab.paused: false → true; center.new added"
        );
        assert!(!rows[3].rules);
        assert_eq!(rows[4].when, "2 min ago");
        assert_eq!(rows[4].index, 4);
    }

    /// The filters combine; each decision counts what the other filters
    /// leave; the order turns; the rows keep their entry's index.
    #[test]
    fn the_audit_filters_combine_and_count() {
        let paired = vec!["home".to_string(), "lab".to_string()];
        let at = |mut v: Value, ts: u64| {
            v["ts"] = json!(ts);
            v
        };
        let oldest_first = [
            at(call("git status", "allowed", "home"), 1),
            at(call("rm -rf /srv", "forbidden", "lab"), 2),
            json!({"ts": 3, "center": "home", "cap": "fs", "action": "read", "target": "/etc/shadow", "decision": "forbidden", "reason": "protected path"}),
            json!({"ts": 4, "kind": "settings", "by": "center lab", "version": 2,
                "changes": [{"key": "center.lab.policy.mode", "old": "allowlist", "new": "user"}]}),
            json!({"ts": 5, "kind": "settings", "by": "local", "version": 3,
                "changes": [{"key": "log.level", "old": "info", "new": "debug"}]}),
            json!({"ts": 6, "kind": "config", "event": "refused", "file": "/etc/nerve/node.toml", "reason": "changed outside"}),
            at(call("git push", "allowed", "lab"), 7),
            json!({"ts": 8, "kind": "audit", "event": "cleared", "user": "alice"}),
        ];
        let newest: Vec<Value> = oldest_first.iter().rev().cloned().collect();
        let view = |f: AuditFilter| audit_view(&newest, &paired, &f, 200, NOW);
        let all = view(AuditFilter::default());
        assert_eq!(all.counts, [8, 2, 3, 2]);
        assert_eq!(all.matches, 8);
        assert_eq!(all.rows.len(), 8);
        assert_eq!(all.rows[0].kind, "audit");
        assert_eq!(all.centers, ["home", "lab"]);
        assert_eq!(all.actions, ["exec.run", "fs.read"]);
        // Refused, at lab: the call and the change lab made are lab's, the
        // config file nobody's.
        let lab = view(AuditFilter {
            center: "lab".into(),
            ..Default::default()
        });
        assert_eq!(lab.counts, [3, 1, 1, 1]);
        let refused_lab = view(AuditFilter {
            center: "lab".into(),
            decision: 2,
            ..Default::default()
        });
        assert_eq!(refused_lab.matches, 1);
        assert_eq!(refused_lab.rows[0].target, "rm -rf /srv");
        assert_eq!(refused_lab.rows[0].index, 6);
        assert!(refused_lab.rows[0].rules);
        // An action: calls only.
        let runs = view(AuditFilter {
            action: "exec.run".into(),
            ..Default::default()
        });
        assert_eq!(runs.counts, [3, 2, 1, 0]);
        // Words in the target and the reason, any case, every one; a
        // change's keys.
        let found = view(AuditFilter {
            text: "PROTECTED shadow".into(),
            ..Default::default()
        });
        assert_eq!(found.matches, 1);
        assert_eq!(found.rows[0].title, "fs.read");
        let keys = view(AuditFilter {
            text: "log.level".into(),
            decision: 3,
            ..Default::default()
        });
        assert_eq!(keys.matches, 1);
        assert_eq!(
            view(AuditFilter {
                text: "nothing like it".into(),
                ..Default::default()
            })
            .matches,
            0
        );
        // Oldest first, and a limit that leaves the count.
        let old = audit_view(
            &newest,
            &paired,
            &AuditFilter {
                oldest_first: true,
                ..Default::default()
            },
            3,
            NOW,
        );
        assert_eq!(old.matches, 8);
        let targets: Vec<&str> = old.rows.iter().map(|r| r.target.as_str()).collect();
        assert_eq!(targets, ["git status", "rm -rf /srv", "/etc/shadow"]);
        assert_eq!(old.rows[0].index, 7);
        assert!(!AuditFilter::default().is_set());
        assert!(
            AuditFilter {
                text: " x ".into(),
                ..Default::default()
            }
            .is_set()
        );
    }

    #[test]
    fn a_button_runs_rule_add_with_the_entrys_action() {
        let e = call("git status", "forbidden", "home");
        assert_eq!(
            rule_args(&e, "allow", true),
            [
                "rule",
                "add",
                "allow",
                "git status",
                "--action=exec.run",
                "--center=home",
                "--wildcard"
            ]
        );
        // A sudo command goes on the sudo list; a deny on the deny list.
        let e = call("sudo apt update", "forbidden", "home");
        assert_eq!(rule_args(&e, "allow", false)[2], "sudo");
        assert_eq!(rule_args(&e, "deny", false)[2], "deny");
        let e = json!({"center": "home", "cap": "fs", "action": "write", "target": "/srv/a"});
        assert_eq!(
            rule_args(&e, "deny", false)[3..5],
            ["/srv/a", "--action=fs.write"]
        );
    }

    #[test]
    fn the_permissions_of_a_center() {
        let f = folders(
            &json!({"folders": [{"path": "/srv/a", "read": true, "write": false, "execute": true}]}),
        );
        assert_eq!(
            (f[0].path.as_str(), f[0].read, f[0].write, f[0].execute),
            ("/srv/a", true, false, true)
        );
        assert_eq!(rights(true, false, true), "=rx");
        assert_eq!(rights(false, false, false), "=");
        let rows = caps(&json!({"caps": {"exec.run": "off", "fs": "hidden"},
            "known": {"exec": ["run", "signal"], "fs": ["read"]}}));
        let names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["exec", "exec.run", "exec.signal", "fs", "fs.read"]);
        assert_eq!((rows[0].setting, rows[0].set), (0, false));
        assert_eq!(
            (rows[1].setting, rows[1].set, rows[1].action),
            (1, true, true)
        );
        assert_eq!(rows[3].setting, 2);
        assert_eq!(cap_word(2), "hidden");
        let c = json!({"mode": "user", "until": NOW + 90 * 60_000});
        assert_eq!(mode_until(&c, NOW), "Back to allowlist mode in 1 h.");
        assert_eq!(mode_until(&json!({"mode": "user"}), NOW), "");
        let login = |u: &str, t: &str| proxy_login(u, t);
        assert_eq!(
            login("http://p.example:3128", ""),
            ("http://p.example:3128".into(), None)
        );
        assert_eq!(
            login("http://alice:s%40cret@p.example:3128", ""),
            ("http://alice@p.example:3128".into(), Some("s@cret".into()))
        );
        assert_eq!(
            login("http://alice@p.example:3128", "typed"),
            ("http://alice@p.example:3128".into(), Some("typed".into()))
        );
        assert_eq!(
            login("http://alice:old@p.example:3128", "typed"),
            ("http://alice@p.example:3128".into(), Some("typed".into()))
        );
    }

    #[test]
    fn the_log_newest_first_or_its_problems() {
        let lines = [
            json!({"ts": NOW, "level": "error", "msg": "cannot connect"}),
            json!({"ts": NOW, "level": "info", "msg": "node started"}),
            json!({"ts": NOW, "level": "warn", "msg": "link dropped", "node": "web-1"}),
        ];
        let rows = log_rows(&lines, false, NOW);
        assert_eq!(rows.len(), 3);
        assert_eq!(
            (rows[0].level.as_str(), rows[0].tone),
            ("Error", Tone::Danger)
        );
        let rows = log_rows(&lines, true, NOW);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].msg, "link dropped (web-1)");
    }

    #[test]
    fn times_in_words() {
        assert_eq!(ago(NOW - 10_000, NOW), "just now");
        assert_eq!(ago(NOW - 5 * 3_600_000, NOW), "5 h ago");
        assert_eq!(ago(NOW - 3 * 86_400_000, NOW), "3 days ago");
        assert_eq!(exact(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(exact(1_760_800_000_000), "2025-10-18 15:06:40 UTC");
    }

    /// A center's page shows the failed grants of its own folders, those
    /// of the folders above them on the way, and the node's own errors; not
    /// another center's.
    #[test]
    fn a_center_sees_the_failed_grants_of_its_own_folders() {
        let errors = [
            "/home/o/proj/sub: Permission denied (os error 13)",
            "/home/o/proj: nerve-run cannot reach it, as /home is closed to it and not yours",
            "/home: Permission denied (os error 13)",
            "/home/o/other: its file system does not support POSIX ACLs",
            "cannot act as o: Operation not permitted",
        ];
        let errors = errors.map(String::from);
        let got = grant_errors_for(&errors, &["~/proj".into()], Path::new("/home/o"));
        assert_eq!(
            got,
            [&errors[0], &errors[1], &errors[2], &errors[4]].map(String::clone)
        );
        assert_eq!(
            grant_errors_for(&errors, &["/home/o/other".into()], Path::new("/x")),
            [&errors[2], &errors[3], &errors[4]].map(String::clone)
        );
    }

    /// Access nerve-run should have lost is told apart from the failed
    /// grants: a folder removed from every center whose entries did not
    /// come off, and the node's record that could not be read, with their
    /// errors; a stale path no error names is told as it is (#142).
    #[test]
    fn access_that_should_have_gone_is_told_apart() {
        let stale = [
            "/home/o/gone",
            "/var/lib/nerve/state/acl.json",
            "/home/o/quiet",
        ]
        .map(String::from);
        let errors = [
            "/home/o/gone/sub: Permission denied (os error 13)",
            "/var/lib/nerve/state/acl.json: expected value at line 1 column 1",
            "/home/o/proj: Permission denied (os error 13)",
            "/home/o/gonetoo: not this one",
        ]
        .map(String::from);
        let (kept, rest) = stale_grants(&stale, &errors);
        assert_eq!(kept, [&errors[0], &errors[1], &stale[2]].map(String::clone));
        assert_eq!(rest, [&errors[2], &errors[3]].map(String::clone));
        // Neither is in a center's list: the per-center filter alone would
        // show their errors nowhere.
        assert_eq!(
            grant_errors_for(&errors, &["~/proj".into()], Path::new("/home/o")),
            [&errors[2]].map(String::clone)
        );
    }
}
