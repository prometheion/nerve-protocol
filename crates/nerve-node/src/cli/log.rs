//! `nerve-node audit` and `nerve-node log`: what was allowed and refused,
//! and the node's own log, also as they grow.

use nerve_policy::rules::visible;
use nerve_service::out;

use super::*;

/// `audit clear`: starts the audit log afresh, keeping the entries so far
/// aside.
pub(super) async fn audit_clear(paths: NodePaths, out: &mut dyn Write) -> Result<(), String> {
    // A command of a center must not wipe what it did from the
    // owner's sight.
    owner_check(&[&paths]).await?;
    let who = changed_by();
    AuditLog::new(paths.audit_log())
        .clear(&who)
        .map_err(|e| format!("{}: {e}", paths.audit_log().display()))?;
    w(
        out,
        format!(
            "audit cleared; the entries so far are kept in {}",
            AuditLog::new(paths.audit_log()).old_path().display()
        ),
    );
    Ok(())
}

/// `log clear`: starts the node's log afresh.
pub(super) async fn log_clear(paths: NodePaths, out: &mut dyn Write) -> Result<(), String> {
    owner_check(&[&paths]).await?;
    clear_log(&paths, &changed_by())?;
    w(out, "log cleared".into());
    Ok(())
}

/// One audit entry as a line of text. What a center sent (a call's target,
/// a command, a reason) is written out as `visible` does, so an entry stays
/// one line, nothing in it acts on the terminal, and no line of a command
/// can pass for the program's own `Next:` or `Warning:`.
fn audit_line(v: &Value) -> String {
    let s = |k: &str| match &v[k] {
        // The time as people read it; `--json` keeps the number.
        Value::Number(n) if k == "ts" => n.as_u64().map_or_else(|| n.to_string(), out::time),
        Value::String(s) => visible(s),
        Value::Null => String::new(),
        other => other.to_string(),
    };
    if v.get("changes").is_some() {
        // A local change names the account that made it, when known.
        let user = v["user"]
            .as_str()
            .map_or_else(String::new, |u| format!(" ({})", visible(u)));
        return format!(
            "{}  settings v{} by {}{user}",
            s("ts"),
            s("version"),
            s("by")
        );
    }
    if v["kind"] == "node" {
        let steps: Vec<String> = v["steps"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|s| s.as_str().map(visible))
            .collect();
        let mut line = format!("{}  {}: {}", s("ts"), s("event"), steps.join("; "));
        if let Some(e) = v["error"].as_str() {
            line.push_str(&format!(" (failed: {})", visible(e)));
        }
        return line;
    }
    if v["kind"] == "relay" {
        return format!(
            "{}  relay  {} from {} to center {}: {} after {} ({} bytes up, {} down)",
            s("ts"),
            s("node"),
            s("from"),
            s("center"),
            s("reason"),
            nerve_transport::log::span(Duration::from_millis(
                v["end"]
                    .as_u64()
                    .unwrap_or(0)
                    .saturating_sub(v["start"].as_u64().unwrap_or(0))
            )),
            s("up"),
            s("down"),
        );
    }
    if v["kind"] == "config" {
        return format!(
            "{}  config {}  {}: {}",
            s("ts"),
            s("event"),
            s("file"),
            s("reason")
        );
    }
    if v["kind"] == "audit" {
        return format!("{}  audit {} by {}", s("ts"), s("event"), s("user"));
    }
    if v["kind"] == "key" {
        return format!(
            "{}  {}  key {}: {}",
            s("ts"),
            s("center"),
            s("event"),
            s("detail")
        );
    }
    let line = format!(
        "{}  {}  {}.{}  {}  {}",
        s("ts"),
        s("center"),
        s("cap"),
        s("action"),
        s("target"),
        s("decision")
    );
    let line = match v["reason"].as_str() {
        Some(reason) => format!("{line}: {}", visible(reason)),
        None => line,
    };
    // What a capability of node.toml ran, or would have, for the call.
    match v["command"].as_str() {
        Some(command) => format!("{line} (command: {})", visible(command)),
        None => line,
    }
}

/// `audit`: the log through [`AuditLog::lines`], the rotated file first.
/// `--follow` looks again every 500 ms and shows the lines after the last one
/// it showed, wherever that line is now: in `audit.jsonl.1` after a rotation,
/// so the old file is finished before the new one, or further up after the
/// log dropped old refusals. With `json` the entries are as the log holds
/// them: one list, or with `follow` one JSON line each.
pub(super) async fn audit(
    paths: &NodePaths,
    follow: bool,
    denied: bool,
    last: Option<usize>,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    let log = AuditLog::new(paths.audit_log());
    let mut entries = Vec::new();
    let mut shown = Shown::default();
    // --last cuts what is there at the start; with --follow every new
    // entry comes after it.
    let mut first = true;
    let mut stamp = None;
    loop {
        // Both files as they are now; the same as at the last look is
        // nothing new, and is not read again.
        let now = [log.path().to_path_buf(), log.old_path()].map(|p| {
            std::fs::metadata(p)
                .ok()
                .map(|m| (m.len(), m.modified().ok()))
        });
        if stamp.as_ref() == Some(&now) {
            tokio::time::sleep(Duration::from_millis(500)).await;
            continue;
        }
        stamp = Some(now);
        let lines = log
            .lines()
            .map_err(|e| format!("{}: {e}", log.path().display()))?;
        let mut new: Vec<Value> = lines[shown.next(&lines)..]
            .iter()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|v| {
                !denied
                    || v["decision"].as_str() == Some("forbidden")
                    || v["event"].as_str() == Some("refused")
            })
            .collect();
        if first && let Some(n) = last {
            new.drain(..new.len().saturating_sub(n));
        }
        first = false;
        for v in new {
            match (json, follow) {
                (false, _) => {
                    let _ = writeln!(out, "{}", audit_line(&v));
                }
                (true, false) => entries.push(v),
                (true, true) => {
                    let _ = writeln!(out, "{v}");
                }
            }
        }
        shown.saw(&lines);
        if !follow {
            if json {
                let _ = writeln!(out, "{}", json!({ "entries": entries }));
            }
            return Ok(());
        }
        let _ = out.flush();
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// `log clear`: the node's log and its moved-aside file emptied, and one
/// line in it of who did it. The running node writes on at the end of the
/// emptied file.
fn clear_log(paths: &NodePaths, who: &str) -> Result<(), String> {
    let file = paths.log_file();
    let mut old = file.clone().into_os_string();
    old.push(".1");
    match std::fs::remove_file(&old) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(format!("{}: {e}", Path::new(&old).display()));
        }
        _ => {}
    }
    let line = nerve_transport::log::Entry {
        ts: nerve_proto::msg::now_ms(),
        level: nerve_transport::log::Level::Info,
        node: None,
        node_id: None,
        msg: format!("the log was cleared by {who}"),
    };
    let mut line = serde_json::to_vec(&line).map_err(|e| e.to_string())?;
    line.push(b'\n');
    let mut o = std::fs::OpenOptions::new();
    o.write(true).truncate(true);
    match o.open(&file) {
        Ok(mut f) => f.write_all(&line),
        // No log yet: nothing to clear, and no line either.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
    .map_err(|e| format!("{}: {e}", file.display()))
}

/// `log`: the node's log file, the moved-aside one first (docs/dev/logging.md).
/// `--follow` looks again every 500 ms and reads what was added to the file,
/// or the new file from its start once the old one was moved aside. With
/// `json` the lines are as the file holds them: one list, or with `follow`
/// one JSON line each.
pub(super) async fn log_cmd(
    paths: &NodePaths,
    follow: bool,
    last: Option<usize>,
    problems: bool,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    let file = paths.log_file();
    let read = |p: &Path| match std::fs::read(p) {
        Ok(b) => Ok(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("{}: {e}", p.display())),
    };
    let mut old = file.clone().into_os_string();
    old.push(".1");
    let mut bytes = read(Path::new(&old))?;
    let current = read(&file)?;
    let mut at = current.len();
    // The file's first bytes tell it from the one that replaces it, which
    // can be as long already.
    let head = |b: &[u8]| b[..b.len().min(64)].to_vec();
    let mut first = head(&current);
    // A line the node is still writing waits for its end, also at the
    // start: read now, its first half would be no line, and the rest,
    // read later, none either.
    let whole = current
        .iter()
        .rposition(|b| *b == b'\n')
        .map_or(0, |i| i + 1);
    bytes.extend_from_slice(&current[..whole]);
    let mut rest: Vec<u8> = current[whole..].to_vec();
    // --problems: errors and warnings only, before --last counts them.
    let parse = |bytes: &[u8]| -> Vec<Value> {
        String::from_utf8_lossy(bytes)
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|v| !problems || matches!(v["level"].as_str(), Some("error" | "warn")))
            .collect()
    };
    let mut lines = parse(&bytes);
    if let Some(n) = last {
        lines.drain(..lines.len().saturating_sub(n));
    }
    let show = |out: &mut dyn Write, v: &Value| {
        let _ = if json {
            writeln!(out, "{v}")
        } else {
            writeln!(out, "{}", log_line(v))
        };
    };
    if json && !follow {
        let _ = writeln!(out, "{}", json!({ "entries": lines }));
        return Ok(());
    }
    for v in &lines {
        show(out, v);
    }
    if !follow {
        return Ok(());
    }
    loop {
        let _ = out.flush();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let now = read(&file)?;
        if now.len() < at || !now.starts_with(&first) {
            // Moved aside: what the old file got after the last look, then
            // the new file from its start.
            let moved = read(Path::new(&old))?;
            rest.extend_from_slice(moved.get(at..).unwrap_or_default());
            at = 0;
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
        for v in parse(&done) {
            show(out, &v);
        }
    }
}

/// One line of the log for people: the time, the level, the message.
fn log_line(v: &Value) -> String {
    let mut line = format!(
        "{}  {}  {}",
        out::time(v["ts"].as_u64().unwrap_or_default()),
        visible(v["level"].as_str().unwrap_or_default()),
        visible(v["msg"].as_str().unwrap_or_default())
    );
    if let Some(n) = v["node"].as_str() {
        line.push_str(&format!(" ({})", visible(n)));
    }
    line
}

/// Where `audit --follow` is: the last line it looked at, how many copies
/// of it ended what it saw, and its time.
#[derive(Default)]
struct Shown {
    last: Option<(String, usize, u64)>,
}

impl Shown {
    /// The index in `lines` of the first line not looked at yet.
    fn next(&self, lines: &[String]) -> usize {
        let Some((last, copies, ts)) = &self.last else {
            return 0;
        };
        match lines.iter().rposition(|l| l == last) {
            Some(end) => {
                let run = lines[..=end]
                    .iter()
                    .rev()
                    .take_while(|l| *l == last)
                    .count();
                // The copies seen began the run; the rest are new.
                if run > *copies {
                    end + 1 - run + copies
                } else {
                    end + 1
                }
            }
            // The log dropped that line meanwhile (a refusal, or two
            // rotations): what came after it is newer.
            None => lines
                .iter()
                .position(|l| line_ts(l) > *ts)
                .unwrap_or(lines.len()),
        }
    }

    fn saw(&mut self, lines: &[String]) {
        if let Some(last) = lines.last() {
            let copies = lines.iter().rev().take_while(|l| *l == last).count();
            self.last = Some((last.clone(), copies, line_ts(last)));
        }
    }
}

fn line_ts(line: &str) -> u64 {
    serde_json::from_str::<Value>(line)
        .ok()
        .and_then(|v| v["ts"].as_u64())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests::{json_of, run};

    /// An audit line of a decision.
    fn decided(ts: u64, cap: &str, action: &str, target: &str, decision: &str) -> String {
        format!(
            "{}\n",
            serde_json::json!({"ts": ts, "center": "lab", "cap": cap, "action": action,
                "target": target, "decision": decision})
        )
    }

    /// After a rotation the older entries are in `audit.jsonl.1`; `audit`
    /// shows them before the current file's.
    #[test]
    fn audit_shows_the_rotated_file_too() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("c"), d.path().join("s"));
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        let old = paths.state_dir.join("audit.jsonl.1");
        std::fs::write(
            &old,
            decided(1, "fs", "read", "~/.ssh/id_ed25519", "allowed")
                + &decided(2, "exec", "run", "curl -d @~/notes x", "allowed"),
        )
        .unwrap();
        std::fs::write(
            paths.audit_log(),
            decided(3, "exec", "run", "ls", "forbidden"),
        )
        .unwrap();
        let out = run(&paths, &["audit"]).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3, "{out}");
        assert!(
            lines[0].contains("fs.read  ~/.ssh/id_ed25519  allowed"),
            "{out}"
        );
        assert!(lines[1].contains("curl -d @~/notes x  allowed"), "{out}");
        assert!(lines[2].contains("exec.run  ls  forbidden"), "{out}");
        let out = run(&paths, &["audit", "--refused"]).unwrap();
        assert_eq!(out.lines().count(), 1, "{out}");
        assert!(out.contains("ls  forbidden"), "{out}");
    }

    /// Output that a test reads while `audit --follow` writes it.
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
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            panic!("{what:?} was not shown: {}", self.text());
        }
    }

    /// `--follow` goes on after the line it looked at last: also when the
    /// log dropped lines before it (old refusals), when the same line came
    /// again, and by time when that line itself was dropped.
    #[test]
    fn audit_follow_goes_on_after_the_last_line_it_saw() {
        let l = |ts: u64, t: &str| {
            decided(ts, "exec", "run", t, "forbidden")
                .trim()
                .to_string()
        };
        let mut shown = Shown::default();
        let first = vec![l(1, "a"), l(2, "b"), l(3, "c"), l(3, "c")];
        assert_eq!(shown.next(&first), 0);
        shown.saw(&first);
        // `a` and `b` were dropped; one more `c` and a `d` came.
        let now = vec![l(3, "c"), l(3, "c"), l(3, "c"), l(4, "d")];
        assert_eq!(&now[shown.next(&now)..], &now[2..]);
        shown.saw(&now);
        // `d` itself was dropped: what is newer than it is new.
        let now = vec![l(3, "c"), l(5, "e")];
        assert_eq!(&now[shown.next(&now)..], &now[1..]);
        shown.saw(&now);
        assert_eq!(shown.next(&now), now.len());
    }

    /// `--follow` finishes the old file after a rotation before it reads the
    /// new one: a line written right before the rotation is shown, and each
    /// line once.
    #[tokio::test]
    async fn audit_follow_finishes_the_old_file_after_a_rotation() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("c"), d.path().join("s"));
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        let log = paths.audit_log();
        let append = |line: String| {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log)
                .unwrap();
            f.write_all(line.as_bytes()).unwrap();
        };
        append(decided(1, "fs", "read", "first", "allowed"));
        let seen = Seen::default();
        let mut out = seen.clone();
        let follow = audit(&paths, true, false, None, false, &mut out);
        let writer = async {
            seen.until("first").await;
            append(decided(2, "fs", "read", "before-the-rotation", "allowed"));
            std::fs::rename(&log, paths.state_dir.join("audit.jsonl.1")).unwrap();
            append(decided(3, "fs", "read", "after-the-rotation", "allowed"));
            seen.until("after-the-rotation").await;
            // One more look, which must show nothing twice.
            tokio::time::sleep(Duration::from_millis(1200)).await;
        };
        tokio::select! {
            r = follow => panic!("follow ended: {r:?}"),
            () = writer => {}
        }
        let text = seen.text();
        let shown: Vec<&str> = text
            .lines()
            .map(|l| l.split("fs.read  ").nth(1).unwrap_or(l))
            .collect();
        assert_eq!(
            shown,
            [
                "first  allowed",
                "before-the-rotation  allowed",
                "after-the-rotation  allowed"
            ],
            "{text}"
        );
    }

    #[test]
    fn audit_json_gives_the_entries_as_the_log_holds_them() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("c"), d.path().join("s"));
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        std::fs::write(
            paths.audit_log(),
            decided(1, "fs", "read", "/srv/a", "allowed")
                + &decided(2, "exec", "run", "ls", "forbidden"),
        )
        .unwrap();
        let v = json_of(&paths, &["audit"]);
        let e = v["entries"].as_array().unwrap();
        assert_eq!(e.len(), 2, "{v}");
        assert_eq!(
            (&e[0]["target"], &e[1]["decision"]),
            (&json!("/srv/a"), &json!("forbidden"))
        );
        let v = json_of(&paths, &["audit", "--refused"]);
        assert_eq!(v["entries"].as_array().unwrap().len(), 1, "{v}");
        // The newest only, after --refused picked.
        let v = json_of(&paths, &["audit", "--last", "1"]);
        assert_eq!(v["entries"][0]["target"], "ls", "{v}");
        assert_eq!(v["entries"].as_array().unwrap().len(), 1, "{v}");
        std::fs::write(
            paths.audit_log(),
            decided(1, "exec", "run", "a", "forbidden")
                + &decided(2, "exec", "run", "b", "forbidden")
                + &decided(3, "fs", "read", "/c", "allowed"),
        )
        .unwrap();
        let v = json_of(&paths, &["audit", "--refused", "--last", "1"]);
        assert_eq!(v["entries"].as_array().unwrap().len(), 1, "{v}");
        assert_eq!(v["entries"][0]["target"], "b", "{v}");
        let out = run(&paths, &["audit", "--last", "2"]).unwrap();
        assert_eq!(out.lines().count(), 2, "{out}");
        assert!(out.contains("fs.read  /c"), "{out}");
    }

    fn logged(ts: u64, level: &str, msg: &str) -> String {
        format!("{}\n", json!({"ts": ts, "level": level, "msg": msg}))
    }

    #[test]
    fn log_shows_the_moved_file_first_and_the_newest_with_last() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("c"), d.path().join("s"));
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        std::fs::write(
            paths.state_dir.join("log.jsonl.1"),
            logged(1, "info", "node started"),
        )
        .unwrap();
        std::fs::write(
            paths.log_file(),
            logged(2, "warn", "link dropped") + &logged(3, "error", "cannot connect"),
        )
        .unwrap();
        let out = run(&paths, &["log"]).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines,
            [
                "1970-01-01 00:00:00  info  node started",
                "1970-01-01 00:00:00  warn  link dropped",
                "1970-01-01 00:00:00  error  cannot connect"
            ]
        );
        let v = json_of(&paths, &["log", "--last", "2"]);
        assert_eq!(v["entries"][0]["msg"], "link dropped", "{v}");
        assert_eq!(v["entries"].as_array().unwrap().len(), 2, "{v}");
        // The problems only, the newest first counted: the warning that
        // came before more lines than --last is still found.
        std::fs::write(
            paths.log_file(),
            logged(2, "warn", "link dropped")
                + &logged(3, "info", "linked")
                + &logged(4, "info", "linked again"),
        )
        .unwrap();
        let v = json_of(&paths, &["log", "--problems", "--last", "1"]);
        assert_eq!(v["entries"].as_array().unwrap().len(), 1, "{v}");
        assert_eq!(v["entries"][0]["msg"], "link dropped", "{v}");
        let out = run(&paths, &["log", "--problems"]).unwrap();
        assert_eq!(out, "1970-01-01 00:00:00  warn  link dropped\n");
        // No log yet is no error.
        let empty = NodePaths::new(d.path().join("c2"), d.path().join("s2"));
        assert_eq!(json_of(&empty, &["log"]), json!({"entries": []}));
    }

    /// `log clear` empties the log and its older file and says who did it;
    /// `audit clear` keeps the entries so far as the older file, and the
    /// audit shows only the entry of the clearing then. Neither takes
    /// arguments of the reading form.
    #[test]
    fn log_and_audit_clear_start_afresh_and_say_who() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("c"), d.path().join("s"));
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        // No log yet: nothing to clear, and no error.
        run(&paths, &["log", "clear"]).unwrap();
        assert!(!paths.log_file().exists());
        std::fs::write(
            paths.state_dir.join("log.jsonl.1"),
            logged(1, "info", "node started"),
        )
        .unwrap();
        std::fs::write(paths.log_file(), logged(2, "warn", "link dropped")).unwrap();
        let out = run(&paths, &["log", "clear"]).unwrap();
        assert_eq!(out, "log cleared\n");
        assert!(!paths.state_dir.join("log.jsonl.1").exists());
        let v = json_of(&paths, &["log"]);
        let entries = v["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1, "{v}");
        let who = changed_by();
        assert_eq!(
            entries[0]["msg"],
            format!("the log was cleared by {who}"),
            "{v}"
        );

        let log = AuditLog::new(paths.audit_log());
        log.settings("local", 1, &[]).unwrap();
        log.settings("local", 2, &[]).unwrap();
        let before = std::fs::read(paths.audit_log()).unwrap();
        let v = json_of(&paths, &["audit", "clear"]);
        assert!(
            v["messages"][0]
                .as_str()
                .unwrap()
                .starts_with("audit cleared; the entries so far are kept in "),
            "{v}"
        );
        assert_eq!(std::fs::read(log.old_path()).unwrap(), before);
        let v = json_of(&paths, &["audit"]);
        let entries = v["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1, "{v}");
        assert_eq!(entries[0]["event"], "cleared");
        assert_eq!(entries[0]["user"], who.as_str());
        let out = run(&paths, &["audit"]).unwrap();
        assert!(out.ends_with(&format!("audit cleared by {who}\n")), "{out}");
        for args in [
            &["audit", "clear", "--last", "2"][..],
            &["log", "--follow", "clear"],
        ] {
            assert!(run(&paths, args).is_err(), "{args:?}");
        }
    }

    /// `log --follow` goes on with the new file once the old one is moved
    /// aside, the lines written to the old one before that included.
    #[tokio::test]
    async fn log_follow_goes_on_after_the_file_is_moved_aside() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("c"), d.path().join("s"));
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        let file = paths.log_file();
        let append = |line: String| {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&file)
                .unwrap();
            f.write_all(line.as_bytes()).unwrap();
        };
        append(logged(1, "info", "first"));
        let seen = Seen::default();
        let mut out = seen.clone();
        let follow = log_cmd(&paths, true, Some(5), false, true, &mut out);
        let writer = async {
            seen.until("first").await;
            append(logged(2, "info", "before-the-move"));
            std::fs::rename(&file, paths.state_dir.join("log.jsonl.1")).unwrap();
            append(logged(3, "info", "after-the-move"));
            seen.until("after-the-move").await;
            tokio::time::sleep(Duration::from_millis(1200)).await;
        };
        tokio::select! {
            r = follow => panic!("follow ended: {r:?}"),
            () = writer => {}
        }
        let text = seen.text();
        let msgs: Vec<String> = text
            .lines()
            .map(|l| {
                serde_json::from_str::<Value>(l).unwrap()["msg"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(
            msgs,
            ["first", "before-the-move", "after-the-move"],
            "{text}"
        );
    }

    /// A line half written when `log --follow` starts is shown once it is
    /// whole, not lost.
    #[tokio::test]
    async fn log_follow_waits_for_a_line_half_written_at_its_start() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("c"), d.path().join("s"));
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        let file = paths.log_file();
        let append = |text: &str| {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&file)
                .unwrap();
            f.write_all(text.as_bytes()).unwrap();
        };
        let half = logged(2, "info", "half-written");
        let (start, end) = half.split_at(half.len() / 2);
        append(&logged(1, "info", "first"));
        append(start);
        let seen = Seen::default();
        let mut out = seen.clone();
        let follow = log_cmd(&paths, true, None, false, true, &mut out);
        let writer = async {
            seen.until("first").await;
            append(end);
            seen.until("half-written").await;
        };
        tokio::select! {
            r = follow => panic!("follow ended: {r:?}"),
            () = writer => {}
            () = tokio::time::sleep(Duration::from_secs(5)) => {
                panic!("the line written in two halves never came: {}", seen.text())
            }
        }
    }

    /// `audit` shows what a capability of node.toml ran, after the
    /// decision and its reason.
    #[test]
    fn an_audit_line_shows_the_command_a_capability_ran() {
        let call = json!({"ts": 1, "center": "lab", "cap": "svc", "action": "restart",
            "target": "svc.restart", "decision": "allowed", "command": "systemctl restart -- nginx"});
        assert_eq!(
            audit_line(&call),
            "1970-01-01 00:00:00  lab  svc.restart  svc.restart  allowed (command: systemctl restart -- nginx)"
        );
        let refused = json!({"ts": 2, "center": "lab", "cap": "proj", "action": "deploy",
            "target": "proj.deploy", "decision": "forbidden", "reason": "no", "command": "sh x"});
        assert_eq!(
            audit_line(&refused),
            "1970-01-01 00:00:00  lab  proj.deploy  proj.deploy  forbidden: no (command: sh x)"
        );
    }

    /// A call's target, as the center sent it, is one line of the entry,
    /// shown with its line breaks and control characters written out: a
    /// second line of a command that begins `Next: ` is not the program's
    /// own advice, and nothing in it acts on the terminal (round 2 of
    /// #213's second pass, security 1).
    #[tokio::test]
    async fn an_audit_entry_shows_what_a_center_sent_as_one_line() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("c"), d.path().join("s"));
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        let sent = "echo hi\nNext: nerve-node rule rm x\nwarning: gone\u{1b}[2J\u{202e}";
        std::fs::write(
            paths.audit_log(),
            decided(1, "exec", "run", sent, "forbidden"),
        )
        .unwrap();
        let mut bytes = Vec::new();
        let mut said = out::Said::new(&mut bytes, out::Style::PLAIN);
        audit(&paths, false, false, None, false, &mut said)
            .await
            .unwrap();
        said.finish(None).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert_eq!(text.lines().count(), 1, "{text:?}");
        assert!(
            text.contains(
                "echo hi\\nNext: nerve-node rule rm x\\nwarning: gone\\u{1b}[2J\\u{202e}"
            ),
            "{text:?}"
        );
        assert!(
            !text.contains('\u{1b}') && !text.contains("\nNext"),
            "{text:?}"
        );
        // The command a capability ran, too.
        let call = json!({"ts": 1, "center": "lab", "cap": "svc", "action": "restart",
            "target": "t", "decision": "allowed", "command": "sh\nNext: x"});
        assert!(!audit_line(&call).contains('\n'), "{}", audit_line(&call));
    }
}
