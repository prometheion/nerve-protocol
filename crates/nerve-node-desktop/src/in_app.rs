//! The node's messages in the app's words on Windows (#176). There the app
//! is the only way to the node, and the program it runs is only the app's
//! interface to it, so a command a message names, as `nerve-node folder rm`
//! or `sudo nerve-node update`, becomes the place in the app that does it,
//! in the words of the Help page's reference (crate::reference), and an
//! option of `restore` becomes the box of the app's restore. On Linux the
//! CLI is there for a person too, and the messages stay as they are.

use serde_json::Value;

/// The answer of a command as the app shows it: on Windows its messages,
/// the problem a pairing's check or the proxy found, a center's link status
/// and its error in the app's words.
/// The answer's data stays as it is: a rule may hold backquotes of its own.
pub fn answer(r: Result<Value, String>, windows: bool) -> Result<Value, String> {
    if !windows {
        return r;
    }
    match r {
        Ok(mut v) => {
            if let Some(lines) = v.get_mut("messages").and_then(Value::as_array_mut) {
                lines.iter_mut().for_each(reword_value);
            }
            // The proxy's problem and a center's link status carry the same
            // advice (`proxy set` again) as the messages do.
            if let Some(p) = v.pointer_mut("/check/problem") {
                reword_value(p);
            }
            if let Some(p) = v.pointer_mut("/proxy/problem") {
                reword_value(p);
            }
            if let Some(cs) = v.get_mut("centers").and_then(Value::as_array_mut) {
                cs.iter_mut()
                    .filter_map(|c| c.get_mut("status"))
                    .for_each(reword_value);
            }
            Ok(v)
        }
        Err(e) => Err(reword(&e)),
    }
}

/// A line of the node's own, as the app shows it: in the app's words on
/// Windows.
pub fn text(line: &str, windows: bool) -> String {
    // The node's record of an owner's change names the exact command, with
    // its subcommand and key; a place in the app would lose which change it was.
    if windows && !line.contains("` as an owner") {
        reword(line)
    } else {
        line.to_string()
    }
}

fn reword_value(v: &mut Value) {
    if let Some(s) = v.as_str() {
        *v = Value::from(reword(s));
    }
}

/// The options of `restore`, as the app's restore names them.
const OPTIONS: &[(&str, &str)] = &[
    ("--without-proxy", "\"Leave its proxy out\""),
    ("--secret-storage=file", "\"Keep its keys in files\""),
    ("--secret-storage file", "\"Keep its keys in files\""),
];

/// The commands a span in backquotes may name by one word alone, without
/// `nerve-node`: the others' words are also those of settings and modes
/// (`folder`, `log`).
const ONE_WORD: &[&str] = &["install", "uninstall", "update", "setup", "restore"];

/// `text` with every command in backquotes that the app does as the place
/// in the app, and the options of `restore` as its boxes.
pub fn reword(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = backquote_outside_quotes(rest) {
        let Some(len) = closing_backquote(&rest[start + 1..]) else {
            break;
        };
        out.push_str(&rest[..start]);
        let span = &rest[start + 1..start + 1 + len];
        match place_of(span) {
            Some(words) => out.push_str(&words),
            None => out.push_str(&rest[start..start + len + 2]),
        }
        rest = &rest[start + len + 2..];
    }
    out.push_str(rest);
    for (option, words) in OPTIONS {
        out = out.replace(option, words);
    }
    out
}

/// The backquote that closes a command span: the first one outside the
/// quotes of the command's arguments (a rule may hold a backquote of its own
/// in single or double quotes). Without balanced quotes, the first one.
fn closing_backquote(span: &str) -> Option<usize> {
    let mut quote = None;
    let mut chars = span.char_indices();
    while let Some((i, c)) = chars.next() {
        match (c, quote) {
            ('\\', Some('"')) => {
                chars.next();
            }
            ('"' | '\'', None) => quote = Some(c),
            (q, Some(open)) if q == open => quote = None,
            ('`', None) => return Some(i),
            _ => {}
        }
    }
    span.find('`')
}

/// The first backquote of `text` that is not inside double quotes: the node
/// shows a rule or a command it quotes with `{:?}`, and a backquote in that
/// is the rule's own (PowerShell's escape), not a command of the node's.
fn backquote_outside_quotes(text: &str) -> Option<usize> {
    let mut quoted = false;
    let mut chars = text.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' if quoted => {
                chars.next();
            }
            '"' => quoted = !quoted,
            '`' if !quoted => return Some(i),
            _ => {}
        }
    }
    None
}

/// Where in the app the command `span` is done, in words that stand where
/// the command stood; `None` for what is no command of the node's.
fn place_of(span: &str) -> Option<String> {
    let s = span.strip_prefix("sudo ").unwrap_or(span);
    // Windows' own commands for the service's start and stop.
    for (cmdlet, button) in [
        ("Restart-Service", "Restart"),
        ("Start-Service", "Start"),
        ("Stop-Service", "Stop"),
    ] {
        if s.starts_with(cmdlet) {
            return Some(format!("{button} on the app's Overview"));
        }
    }
    let named = ["nerve-node-desktop ", "nerve-node "]
        .iter()
        .find_map(|p| s.strip_prefix(p));
    let words = named.unwrap_or(s);
    let found = crate::reference::command_of(words)
        .filter(|(name, _)| named.is_some() || name.contains(' ') || ONE_WORD.contains(name));
    match found {
        Some(("install", _)) => Some("Nerve's installer".into()),
        Some(("run", _)) => Some("Start on the app's Overview".into()),
        // What follows a comma says when, and is no step.
        Some((_, (Some(_), _, place))) => Some(format!(
            "the app's {}",
            place.split(", ").next().unwrap_or(place)
        )),
        _ if named.is_some() => Some("the app".into()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A command the node names becomes its place in the app, with or
    /// without `sudo` and its arguments; what names no command stays.
    #[test]
    fn a_command_becomes_its_place_in_the_app() {
        for (said, shown) in [
            (
                "locked: nothing runs until `nerve-node unlock`",
                "locked: nothing runs until the app's Overview › Unlock",
            ),
            (
                "the user nerve is missing; `sudo nerve-node install` makes it again",
                "the user nerve is missing; Nerve's installer makes it again",
            ),
            (
                "run `sudo nerve-node update` first",
                "run the app's Settings › App › Update first",
            ),
            (
                "remove it first with `nerve-node rule rm allow 'git *' --center lab`",
                "remove it first with the app's Permissions › Allowed commands / Forbidden commands",
            ),
            (
                "the relay knows no node lab; `relay add lab` makes one",
                "the relay knows no node lab; the app's Relay › Add a node makes one",
            ),
            (
                "No center is paired; `nerve-node center add '<link>'` pairs one.",
                "No center is paired; the app's Centers › Pair a center pairs one.",
            ),
            (
                "the account that ran `install`",
                "the account that ran Nerve's installer",
            ),
            (
                "Start it (`nerve-node run`, or the service)",
                "Start it (Start on the app's Overview, or the service)",
            ),
            (
                "`Restart-Service nerve-node` lets the service take it",
                "Restart on the app's Overview lets the service take it",
            ),
            ("run `nerve-node …` again", "run the app again"),
            (
                "Restore with --without-proxy, or with --secret-storage file",
                "Restore with \"Leave its proxy out\", or with \"Keep its keys in files\"",
            ),
            // No command: a setting, a mode, an unclosed quote.
            (
                "machine.user is `alice` in `folder` mode",
                "machine.user is `alice` in `folder` mode",
            ),
            ("a lone ` stays", "a lone ` stays"),
            // A rule in single quotes inside a command's span keeps its own.
            (
                "both \"echo `n\" and \"echo `n *\" are on the allow list: remove \"echo `n *\" first with `nerve-node rule rm allow 'echo `n *' --center lab`, and then \"echo `n\" with `nerve-node rule rm allow 'echo `n' --center lab`",
                "both \"echo `n\" and \"echo `n *\" are on the allow list: remove \"echo `n *\" first with the app's Permissions › Allowed commands / Forbidden commands, and then \"echo `n\" with the app's Permissions › Allowed commands / Forbidden commands",
            ),
            // A rule the node quotes keeps its own backquotes.
            (
                "both \"echo `nerve-node status`\" and x: `nerve-node unlock`",
                "both \"echo `nerve-node status`\" and x: the app's Overview › Unlock",
            ),
        ] {
            let got = reword(said);
            assert_eq!(got, shown, "{said}");
            assert!(
                !got.contains("nerve-node") || got.contains("\"echo `nerve-node"),
                "{got}"
            );
        }
    }

    /// The node's record of an owner's change keeps its command on the Log
    /// page; its advice is reworded.
    #[test]
    fn a_record_of_an_owner_change_keeps_its_command() {
        let record =
            "alice runs `nerve-node-desktop config set center.lab.policy.allow x` as an owner";
        assert_eq!(text(record, true), record);
        assert_eq!(
            text("`nerve-node unlock` first", true),
            "the app's Overview › Unlock first"
        );
    }

    /// The proxy's problem and a center's link status name `proxy set`, which
    /// is a place in the app on Windows.
    #[test]
    fn the_proxy_problem_and_a_center_status_are_in_the_app_words() {
        let v = json!({
            "proxy": {"problem": "holds no password; run `nerve-node proxy set` again"},
            "centers": [{"name": "a", "status": "bad proxy: run `nerve-node proxy set` again"}],
        });
        let shown = answer(Ok(v.clone()), true).unwrap();
        assert!(
            !shown["proxy"]["problem"]
                .as_str()
                .unwrap()
                .contains("nerve-node")
        );
        assert!(
            !shown["centers"][0]["status"]
                .as_str()
                .unwrap()
                .contains("nerve-node")
        );
        assert_eq!(answer(Ok(v.clone()), false), Ok(v));
    }

    /// Only Windows gets the app's words, and only the messages, the check's
    /// problem and the error: the answer's data stays.
    #[test]
    fn only_windows_and_only_the_words_change() {
        let v = json!({
            "messages": ["`nerve-node folder rm` removes it"],
            "check": {"problem": "run `nerve-node status`"},
            "rule": "echo `nerve-node status`",
        });
        assert_eq!(answer(Ok(v.clone()), false), Ok(v.clone()));
        let shown = answer(Ok(v), true).unwrap();
        assert_eq!(
            shown["messages"][0],
            "the app's Permissions › Folders removes it"
        );
        assert_eq!(shown["check"]["problem"], "run the app's Overview");
        assert_eq!(shown["rule"], "echo `nerve-node status`");
        let line = "give it a new one with `nerve-node relay token lab`";
        assert_eq!(text(line, false), line);
        assert_eq!(
            text(line, true),
            "give it a new one with the app's Relay › New link"
        );
        let e = "`sudo nerve-node uninstall` removes it".to_string();
        assert_eq!(answer(Err(e.clone()), false), Err(e.clone()));
        assert_eq!(
            answer(Err(e), true),
            Err("the app's Settings › App › Uninstall removes it".into())
        );
    }
}
